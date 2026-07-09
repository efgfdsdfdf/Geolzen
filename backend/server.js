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
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

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

// ── Health Check ────────────────────────────────────────────────
app.get('/api/health', (req, res) => {
  res.json({
    status: 'operational',
    service: 'geolzen-control-plane',
    version: '2.0.4',
    supabase: supabase ? 'connected' : 'sandbox',
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
      } else {
        // OAuth or file-based verification
        const { data: updated, error: updateErr } = await supabase
          .from('targets')
          .update({ verified: true, verification_method: verificationMethod })
          .eq('id', id)
          .select();

        if (updateErr) throw updateErr;
        return res.json({ success: true, target: updated[0] });
      }
    } catch (err) {
      return res.status(500).json({ error: err.message });
    }
  }

  return res.json({ success: true, target: { id, verified: true, verification_method: verificationMethod } });
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

// ── Scan Execution ──────────────────────────────────────────────

// Launch a real scan pipeline (async — returns immediately with job ID)
app.post('/api/targets/:id/scan', async (req, res) => {
  const { id } = req.params;
  const { scanType } = req.body;

  // Pre-flight compliance checks
  if (supabase) {
    try {
      const { data: target } = await supabase
        .from('targets')
        .select('verified')
        .eq('id', id)
        .single();

      if (!target || !target.verified) {
        return res.status(403).json({
          error: 'COMPLIANCE BLOCK: Target domain ownership is not verified. Scan rejected.'
        });
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

// ── Start Server ────────────────────────────────────────────────
if (process.env.NODE_ENV !== 'production' && !process.env.VERCEL) {
  app.listen(PORT, () => {
    console.log(`[GEOLZEN] Control Plane API listening on http://localhost:${PORT}`);
    console.log(`[GEOLZEN] Supabase: ${supabase ? 'CONNECTED' : 'SANDBOX MODE'}`);
    console.log(`[GEOLZEN] Scanner modules loaded: header, ssl, dns, dependency`);
  });
}

module.exports = app;
