/**
 * Geolzen Backend Control Plane API
 * 
 * Express.js server providing:
 *   - Target registration and management
 *   - DNS ownership verification (Cloudflare DoH)
 *   - Rules of Engagement (ROE) digital signature tracking
 *   - Real scan orchestration with SSE live log streaming
 *   - Vulnerability findings CRUD
 *   - Supabase database synchronization
 */

const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const { executeScanPipeline } = require('./workers/scanOrchestrator');
const Anthropic = require('@anthropic-ai/sdk');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());
app.set('trust proxy', 1); // Trust Render's load balancer for correct req.protocol (https)

// ── Supabase Client Initialization ─────────────────────────────
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY;

let supabase = null;
if (supabaseUrl && (supabaseServiceKey || supabaseAnonKey)) {
  supabase = createClient(supabaseUrl, supabaseServiceKey || supabaseAnonKey);
  console.log('[SUPABASE] Connected to Supabase instance.');
} else {
  console.warn('[WARNING] Supabase environment variables missing. Running in sandbox mode.');
}

// Track active scans for SSE streaming
const activeScans = new Map();

// GitHub OAuth Config
const GITHUB_CLIENT_ID = process.env.GITHUB_CLIENT_ID;
const GITHUB_CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET;
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5173';

// Anthropic AI Config
const anthropic = process.env.ANTHROPIC_API_KEY ? new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY }) : null;

// ── Root & Health Check ──────────────────────────────────────────
app.get('/', (req, res) => {
  res.send('Geolzen Security Control Plane API is online and running successfully.');
});

app.get('/api/health', (req, res) => {
  res.json({
    status: 'operational',
    service: 'geolzen-control-plane',
    version: '2.0.4',
    supabase: supabase ? 'connected' : 'sandbox',
    github_oauth: GITHUB_CLIENT_ID ? 'configured' : 'missing',
    uptime: process.uptime(),
    timestamp: new Date().toISOString()
  });
});

// ── Target Endpoints ────────────────────────────────────────────

// List all targets
app.get('/api/targets', async (req, res) => {
  if (supabase) {
    try {
      const { data, error } = await supabase.from('targets').select('*');
      if (error) throw error;
      return res.json(data);
    } catch (err) {
      return res.status(500).json({ error: err.message });
    }
  }
  return res.json([]);
});

// Register a new target
app.post('/api/targets', async (req, res) => {
  const { name, type, organizationId } = req.body;
  if (!name || !type) {
    return res.status(400).json({ error: 'Target name and type are required.' });
  }

  const cleanName = name.toLowerCase().replace(/^(https?:\/\/)?(www\.)?/, '').split('/')[0].trim();
  const token = `gz-verification-token=gz_tkn_${Math.floor(100000 + Math.random() * 900000)}`;

  if (supabase) {
    try {
      const { data, error } = await supabase
        .from('targets')
        .insert({
          name: cleanName,
          type,
          verified: false,
          verification_method: type === 'domain' ? 'dns' : 'oauth',
          verification_token: token,
          organization_id: organizationId
        })
        .select();

      if (error) throw error;
      return res.status(201).json(data[0]);
    } catch (err) {
      return res.status(500).json({ error: err.message });
    }
  }

  // Sandbox fallback
  return res.status(201).json({
    id: `target-${Date.now()}`,
    name: cleanName,
    type,
    verified: false,
    verification_method: type === 'domain' ? 'dns' : 'oauth',
    verification_token: token
  });
});

// Delete a target
app.delete('/api/targets/:id', async (req, res) => {
  const { id } = req.params;
  if (supabase) {
    try {
      const { error } = await supabase.from('targets').delete().eq('id', id);
      if (error) throw error;
      return res.json({ success: true });
    } catch (err) {
      return res.status(500).json({ error: err.message });
    }
  }
  return res.json({ success: true });
});

// ── DNS Ownership Verification ──────────────────────────────────

app.post('/api/targets/:id/verify', async (req, res) => {
  const { id } = req.params;
  const { verificationMethod } = req.body;

  if (supabase) {
    try {
      const { data: target, error } = await supabase
        .from('targets')
        .select('*')
        .eq('id', id)
        .single();

      if (error || !target) {
        return res.status(404).json({ error: 'Target not found in database.' });
      }

      if (verificationMethod === 'dns' && target.type === 'domain') {
        // Query Cloudflare DoH for TXT records
        const response = await fetch(
          `https://cloudflare-dns.com/dns-query?name=${target.name}&type=TXT`,
          { headers: { 'Accept': 'application/dns-json' } }
        );
        const dnsData = await response.json();
        const answers = dnsData.Answer || [];
        const txtRecords = answers.filter(a => a.type === 16);

        const tokenFound = txtRecords.some(rec => {
          const content = rec.data.replace(/"/g, '');
          return content.includes(target.verification_token);
        });

        if (tokenFound) {
          const { data: updated, error: updateErr } = await supabase
            .from('targets')
            .update({ verified: true, verification_method: 'dns' })
            .eq('id', id)
            .select();

          if (updateErr) throw updateErr;
          return res.json({ success: true, target: updated[0] });
        } else {
          return res.status(400).json({
            success: false,
            message: `TXT record containing "${target.verification_token}" was not found on nameservers for ${target.name}.`,
            recordsRead: txtRecords.map(r => r.data).join(', ') || 'No TXT records found'
          });
        }
      } else if (verificationMethod === 'file' && target.type === 'domain') {
        // Meta file verification: fetch /.well-known/securescan-verify.txt
        try {
          const controller = new AbortController();
          const timeout = setTimeout(() => controller.abort(), 10000);

          const fileUrl = `https://${target.name}/.well-known/securescan-verify.txt`;
          const fileResponse = await fetch(fileUrl, {
            signal: controller.signal,
            headers: { 'User-Agent': 'Geolzen-Verification/1.0' }
          });

          clearTimeout(timeout);

          if (!fileResponse.ok) {
            return res.status(400).json({
              success: false,
              message: `Could not fetch verification file at ${fileUrl}. HTTP status: ${fileResponse.status}. Please ensure the file is publicly accessible.`
            });
          }

          const fileContent = await fileResponse.text();
          const tokenFound = fileContent.trim().includes(target.verification_token);

          if (tokenFound) {
            const { data: updated, error: updateErr } = await supabase
              .from('targets')
              .update({ verified: true, verification_method: 'file' })
              .eq('id', id)
              .select();

            if (updateErr) throw updateErr;
            return res.json({ success: true, target: updated[0] });
          } else {
            return res.status(400).json({
              success: false,
              message: `The file at ${fileUrl} was found but does not contain the expected token "${target.verification_token}".`,
              contentPreview: fileContent.substring(0, 200)
            });
          }
        } catch (fetchErr) {
          if (fetchErr.name === 'AbortError') {
            return res.status(400).json({
              success: false,
              message: `Timed out after 10 seconds trying to reach https://${target.name}/.well-known/securescan-verify.txt`
            });
          }
          return res.status(400).json({
            success: false,
            message: `Failed to reach verification file: ${fetchErr.message}. Please check that https://${target.name}/.well-known/securescan-verify.txt is publicly accessible.`
          });
        }
      } else {
        // OAuth verification — not applicable without a real OAuth flow
        return res.status(400).json({
          success: false,
          message: 'Unsupported verification method. Use DNS TXT or meta file verification for domains.'
        });
      }
    } catch (err) {
      return res.status(500).json({ error: err.message });
    }
  }

  return res.status(400).json({ success: false, message: 'Verification requires a database connection. Please configure Supabase environment variables.' });
});

// ── GitHub OAuth Flow ───────────────────────────────────────────

// Step 1: Redirect user to GitHub authorization page
app.get('/api/auth/github', (req, res) => {
  const { targetId } = req.query;
  if (!GITHUB_CLIENT_ID) {
    return res.status(500).json({ error: 'GitHub OAuth is not configured. Set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET environment variables.' });
  }

  const redirectUri = `${req.protocol}://${req.get('host')}/api/auth/github/callback`;
  const state = targetId || '';
  const githubUrl = `https://github.com/login/oauth/authorize?client_id=${GITHUB_CLIENT_ID}&redirect_uri=${encodeURIComponent(redirectUri)}&scope=repo&state=${encodeURIComponent(state)}`;

  res.redirect(githubUrl);
});

// Step 2: Handle GitHub callback, verify repo ownership
app.get('/api/auth/github/callback', async (req, res) => {
  const { code, state: targetId } = req.query;

  if (!code) {
    return res.redirect(`${FRONTEND_URL}?github_error=no_code`);
  }

  try {
    // Exchange code for access token
    const tokenResponse = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: JSON.stringify({
        client_id: GITHUB_CLIENT_ID,
        client_secret: GITHUB_CLIENT_SECRET,
        code
      })
    });

    const tokenData = await tokenResponse.json();

    if (tokenData.error || !tokenData.access_token) {
      return res.redirect(`${FRONTEND_URL}?github_error=${encodeURIComponent(tokenData.error_description || 'token_exchange_failed')}`);
    }

    const accessToken = tokenData.access_token;

    // Fetch the authenticated GitHub user
    const userResponse = await fetch('https://api.github.com/user', {
      headers: { 'Authorization': `Bearer ${accessToken}`, 'User-Agent': 'Geolzen-App' }
    });
    const githubUser = await userResponse.json();

    if (!targetId || !supabase) {
      return res.redirect(`${FRONTEND_URL}?github_error=missing_target_or_db`);
    }

    // Get target from database
    const { data: target, error: targetErr } = await supabase
      .from('targets')
      .select('*')
      .eq('id', targetId)
      .single();

    if (targetErr || !target) {
      return res.redirect(`${FRONTEND_URL}?github_error=target_not_found`);
    }

    // Check if the user has access to the repository
    // target.name might be "owner/repo", "repo", or a full URL "github.com/owner/repo"
    let repoName = target.name.replace(/^(https?:\/\/)?(www\.)?github\.com\//, '').trim();
    
    // Remove any trailing slashes
    repoName = repoName.replace(/\/$/, '');

    const repoUrl = repoName.includes('/') 
      ? `https://api.github.com/repos/${repoName}`
      : `https://api.github.com/repos/${githubUser.login}/${repoName}`;

    const repoResponse = await fetch(repoUrl, {
      headers: { 'Authorization': `Bearer ${accessToken}`, 'User-Agent': 'Geolzen-App' }
    });

    if (!repoResponse.ok) {
      return res.redirect(`${FRONTEND_URL}?github_error=${encodeURIComponent(`Repository "${repoName}" not found or you do not have access.`)}`);
    }

    const repoData = await repoResponse.json();

    // Verify the user has admin or push permissions
    if (!repoData.permissions || (!repoData.permissions.admin && !repoData.permissions.push)) {
      return res.redirect(`${FRONTEND_URL}?github_error=${encodeURIComponent(`You do not have write access to "${repoName}". Only repository owners or collaborators with push access can verify.`)}`);
    }

    // Verification passed — mark target as verified
    const { error: updateErr } = await supabase
      .from('targets')
      .update({ verified: true, verification_method: 'oauth' })
      .eq('id', targetId);

    if (updateErr) {
      return res.redirect(`${FRONTEND_URL}?github_error=${encodeURIComponent(updateErr.message)}`);
    }

    // Redirect back to frontend with success
    return res.redirect(`${FRONTEND_URL}?github_verified=${targetId}`);

  } catch (err) {
    return res.redirect(`${FRONTEND_URL}?github_error=${encodeURIComponent(err.message)}`);
  }
});

// ── Rules of Engagement Signature ───────────────────────────────

app.post('/api/targets/:id/sign-roe', async (req, res) => {
  const { id } = req.params;
  const { signerName, signerCompany } = req.body;

  if (!signerName || !signerCompany) {
    return res.status(400).json({ error: 'Signer name and company are required.' });
  }

  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';

  if (supabase) {
    try {
      const { data, error } = await supabase
        .from('roe_signatures')
        .insert({
          target_id: id,
          signer_name: signerName,
          signer_company: signerCompany,
          ip_address: clientIp
        })
        .select();

      if (error) throw error;
      return res.status(201).json({ success: true, signature: data[0] });
    } catch (err) {
      return res.status(500).json({ error: err.message });
    }
  }

  return res.status(201).json({
    success: true,
    signature: {
      id: `sig-${Date.now()}`,
      target_id: id,
      signer_name: signerName,
      signer_company: signerCompany,
      ip_address: clientIp,
      signed_at: new Date().toISOString()
    }
  });
});

// ── Analyst Chat API (Anthropic) ──────────────────────────────────
app.post('/api/chat', async (req, res) => {
  const { vulnerability, chatHistory } = req.body;
  
  if (!vulnerability || !chatHistory) {
    return res.status(400).json({ error: 'Missing vulnerability context or chat history' });
  }
  if (!anthropic) {
    return res.status(500).json({ error: 'Anthropic API is not configured on the backend.' });
  }

  try {
    const systemPrompt = `You are a Senior Web Security Analyst at Geolzen Security. 
A user is asking a question about a vulnerability found on their infrastructure.
Vulnerability Context:
- Title: ${vulnerability.title}
- Severity: ${vulnerability.severity}
- Description: ${vulnerability.description}
- Solution: ${vulnerability.solution}
- File/Endpoint: ${vulnerability.fileName}

Provide actionable, concise, and expert advice. Do not output markdown code blocks unless writing code. Keep it under 150 words.`;

    let messages = chatHistory.map(msg => ({
      role: msg.sender === 'user' ? 'user' : 'assistant',
      content: msg.text
    }));

    // Anthropic API requires the first message to be from 'user'
    if (messages.length > 0 && messages[0].role !== 'user') {
      messages.unshift({ role: 'user', content: 'Can you help me with this vulnerability?' });
    }

    const response = await anthropic.messages.create({
      model: 'claude-sonnet-4-5-20250929',
      max_tokens: 300,
      system: systemPrompt,
      messages: messages
    });

    const analystText = response.content[0].text;
    return res.json({ success: true, text: analystText });
  } catch (err) {
    console.error('[ERROR] Anthropic API failure:', err);
    return res.status(500).json({ error: err.message || 'Failed to generate analyst response.' });
  }
});

// ── Scan Execution ──────────────────────────────────────────────

// Launch a real scan pipeline (async — returns immediately with job ID)
app.post('/api/targets/:id/scan', async (req, res) => {
  const { id } = req.params;
  const { scanType, userEmail, sendEmailAlerts } = req.body;
  let verifiedTier = 'free';

  // Pre-flight compliance checks
  if (supabase) {
    try {
      const { data: target } = await supabase
        .from('targets')
        .select(`
          verified,
          organization_id,
          organizations ( plan_tier )
        `)
        .eq('id', id)
        .single();

      if (!target || !target.verified) {
        return res.status(403).json({
          error: 'COMPLIANCE BLOCK: Target domain ownership is not verified. Scan rejected.'
        });
      }

      if (target.organizations && target.organizations.plan_tier) {
        verifiedTier = target.organizations.plan_tier;
      }

      const { data: sig } = await supabase
        .from('roe_signatures')
        .select('id')
        .eq('target_id', id)
        .limit(1);

      if (!sig || sig.length === 0) {
        return res.status(403).json({
          error: 'COMPLIANCE BLOCK: Signed Rules of Engagement (ROE) document is missing. Scan rejected.'
        });
      }
    } catch (err) {
      return res.status(500).json({ error: err.message });
    }
  }

  // Generate a job ID and start the scan asynchronously
  const jobId = `job-${Date.now()}`;
  const scanLogs = [];

  activeScans.set(jobId, {
    targetId: id,
    status: 'running',
    logs: scanLogs,
    startTime: new Date().toISOString()
  });

  // Return immediately with the job ID
  res.status(202).json({
    success: true,
    message: 'Scan pipeline initiated. Stream logs via GET /api/scans/:jobId/stream.',
    jobId
  });

  // Execute scan pipeline in the background
  executeScanPipeline({
    supabase,
    targetId: id,
    scanType: scanType || 'passive',
    tier: verifiedTier,
    userEmail: userEmail || 'user@geolzen.com',
    sendEmailAlerts: sendEmailAlerts !== false,
    onLog: (msg) => {
      const entry = { timestamp: new Date().toISOString(), message: msg };
      scanLogs.push(entry);

      // Emit to any connected SSE clients
      const scan = activeScans.get(jobId);
      if (scan && scan.sseClients) {
        scan.sseClients.forEach(client => {
          client.write(`data: ${JSON.stringify(entry)}\n\n`);
        });
      }
    }
  }).then(result => {
    const scan = activeScans.get(jobId);
    if (scan) {
      scan.status = result.success ? 'completed' : 'failed';
      scan.result = result;

      // Notify SSE clients of completion
      if (scan.sseClients) {
        scan.sseClients.forEach(client => {
          client.write(`data: ${JSON.stringify({ type: 'complete', result })}\n\n`);
          client.end();
        });
      }
    }
  }).catch(err => {
    const scan = activeScans.get(jobId);
    if (scan) {
      scan.status = 'failed';
      scan.error = err.message;
    }
  });
});

// Server-Sent Events endpoint for live scan log streaming
app.get('/api/scans/:jobId/stream', (req, res) => {
  const { jobId } = req.params;
  const scan = activeScans.get(jobId);

  if (!scan) {
    return res.status(404).json({ error: 'Scan job not found.' });
  }

  // Set up SSE headers
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'Access-Control-Allow-Origin': '*'
  });

  // Send any existing logs first
  for (const entry of scan.logs) {
    res.write(`data: ${JSON.stringify(entry)}\n\n`);
  }

  // If scan is already done, send completion and close
  if (scan.status !== 'running') {
    res.write(`data: ${JSON.stringify({ type: 'complete', result: scan.result })}\n\n`);
    return res.end();
  }

  // Register this client for live updates
  if (!scan.sseClients) scan.sseClients = [];
  scan.sseClients.push(res);

  // Clean up on disconnect
  req.on('close', () => {
    if (scan.sseClients) {
      scan.sseClients = scan.sseClients.filter(c => c !== res);
    }
  });
});

// Get scan job status
app.get('/api/scans/:jobId', (req, res) => {
  const { jobId } = req.params;
  const scan = activeScans.get(jobId);

  if (!scan) {
    return res.status(404).json({ error: 'Scan job not found.' });
  }

  return res.json({
    jobId,
    targetId: scan.targetId,
    status: scan.status,
    startTime: scan.startTime,
    logsCount: scan.logs.length,
    result: scan.result || null
  });
});

// ── Vulnerability Endpoints ─────────────────────────────────────

// Get all vulnerabilities for a target
app.get('/api/targets/:id/vulnerabilities', async (req, res) => {
  const { id } = req.params;
  if (supabase) {
    try {
      const { data, error } = await supabase
        .from('vulnerabilities')
        .select('*')
        .eq('target_id', id)
        .order('created_at', { ascending: false });

      if (error) throw error;
      return res.json(data);
    } catch (err) {
      return res.status(500).json({ error: err.message });
    }
  }
  return res.json([]);
});

// Mark a vulnerability as remediated
app.patch('/api/vulnerabilities/:id/remediate', async (req, res) => {
  const { id } = req.params;
  if (supabase) {
    try {
      const { data, error } = await supabase
        .from('vulnerabilities')
        .update({ remediated: true })
        .eq('id', id)
        .select();

      if (error) throw error;
      return res.json({ success: true, vulnerability: data[0] });
    } catch (err) {
      return res.status(500).json({ error: err.message });
    }
  }
  return res.json({ success: true });
});

// ── Chat Messages ───────────────────────────────────────────────

app.get('/api/vulnerabilities/:id/chat', async (req, res) => {
  const { id } = req.params;
  if (supabase) {
    try {
      const { data, error } = await supabase
        .from('chat_messages')
        .select('*')
        .eq('vulnerability_id', id)
        .order('created_at', { ascending: true });

      if (error) throw error;
      return res.json(data);
    } catch (err) {
      return res.status(500).json({ error: err.message });
    }
  }
  return res.json([]);
});

app.post('/api/vulnerabilities/:id/chat', async (req, res) => {
  const { id } = req.params;
  const { sender, message } = req.body;
  if (supabase) {
    try {
      const { data, error } = await supabase
        .from('chat_messages')
        .insert({ vulnerability_id: id, sender, message })
        .select();

      if (error) throw error;
      return res.status(201).json(data[0]);
    } catch (err) {
      return res.status(500).json({ error: err.message });
    }
  }
  return res.status(201).json({ id: `msg-${Date.now()}`, vulnerability_id: id, sender, message });
});

// ── Paystack Integration ──────────────────────────────────────────
const crypto = require('crypto');
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY;

// Verify a payment directly from the frontend
app.post('/api/payments/verify', async (req, res) => {
  const { reference, plan, organization_id } = req.body;
  if (!PAYSTACK_SECRET_KEY) {
    return res.status(500).json({ error: 'Paystack is not configured on the backend.' });
  }

  try {
    const response = await fetch(`https://api.paystack.co/transaction/verify/${reference}`, {
      headers: {
        Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`
      }
    });
    const data = await response.json();

    if (data.status && data.data.status === 'success') {
      // Payment verified! Update the database
      if (supabase && organization_id) {
        await supabase
          .from('organizations')
          .update({
            plan_tier: plan,
            paystack_customer_id: data.data.customer.customer_code,
            subscription_status: 'active'
          })
          .eq('id', organization_id);
      }
      return res.json({ success: true, message: 'Payment verified successfully', data: data.data });
    } else {
      return res.status(400).json({ success: false, message: 'Payment verification failed' });
    }
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// Paystack Webhook for recurring payments or asynchronous events
app.post('/api/webhooks/paystack', (req, res) => {
  if (!PAYSTACK_SECRET_KEY) return res.sendStatus(400);

  // Validate event
  const hash = crypto.createHmac('sha512', PAYSTACK_SECRET_KEY).update(JSON.stringify(req.body)).digest('hex');
  if (hash !== req.headers['x-paystack-signature']) {
    return res.sendStatus(400);
  }

  const event = req.body;

  if (event.event === 'charge.success') {
    // A successful charge was made (could be initial or recurring)
    const customerCode = event.data.customer.customer_code;
    const planId = event.data.plan;
    
    // In a real implementation, you'd map planId to your 'starter' or 'team' string
    // and update the organization's plan_tier where paystack_customer_id = customerCode.
  }

  res.sendStatus(200);
});

// ── Server Start ────────────────────────────────────────────────
if (!process.env.VERCEL) {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[GEOLZEN] Control Plane API listening on http://0.0.0.0:${PORT}`);
    console.log(`[GEOLZEN] Supabase: ${supabase ? 'CONNECTED' : 'SANDBOX MODE'}`);
    console.log(`[GEOLZEN] Scanner modules loaded: header, ssl, dns, dependency`);
  });
}

module.exports = app;
