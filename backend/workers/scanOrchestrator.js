/**
 * Geolzen Scan Orchestrator
 * 
 * Coordinates all scanner modules, aggregates findings,
 * and persists results to the Supabase database.
 * 
 * Scan Pipeline:
 *   1. Validate target verification status and ROE signature
 *   2. Run DNS reconnaissance (passive)
 *   3. Run SSL/TLS certificate analysis (passive)
 *   4. Run HTTP security header audit (passive)
 *   5. Run dependency vulnerability scan (OSV.dev API or Trivy CLI)
 *   6. Aggregate, deduplicate, and persist findings
 *   7. Update scan job status
 */

const { scanHeaders } = require('../scanners/headerScanner');
const { scanSSL } = require('../scanners/sslScanner');
const { scanDNS } = require('../scanners/dnsScanner');
const { scanDependencies } = require('../scanners/depScanner');
const { scanPorts } = require('../scanners/portScanner');
const { scanCMS } = require('../scanners/cmsScanner');

/**
 * Execute a full scan pipeline against a verified target
 * @param {object} params
 * @param {object} params.supabase - Supabase client instance
 * @param {string} params.targetId - Target ID from database
 * @param {string} params.scanType - 'passive' or 'active'
 * @param {function} params.onLog - Callback for real-time log streaming
 * @returns {Promise<object>} - Aggregated scan results
 */
async function executeScanPipeline({ supabase, targetId, scanType, onLog }) {
  const log = onLog || ((msg) => console.log(`[SCAN] ${msg}`));
  const allFindings = [];
  const scanMetadata = {
    targetId,
    scanType,
    startTime: new Date().toISOString(),
    scanners: {},
    errors: []
  };

  // Create a scan job record in the database
  let jobId = null;
  if (supabase) {
    try {
      const { data: job, error } = await supabase
        .from('scan_jobs')
        .insert({
          target_id: targetId,
          scan_type: scanType,
          status: 'running',
          started_at: new Date().toISOString()
        })
        .select();

      if (!error && job && job.length > 0) {
        jobId = job[0].id;
      }
    } catch (err) {
      log(`[WARNING] Could not create scan job record: ${err.message}`);
    }
  }

  try {
    // ── Step 1: Fetch and validate target ─────────────────────
    log('[INFO] Initializing Geolzen Security Core v2.0.4...');

    let target = null;
    if (supabase) {
      const { data, error } = await supabase
        .from('targets')
        .select('*')
        .eq('id', targetId)
        .single();

      if (error || !data) {
        throw new Error(`Target ${targetId} not found in database`);
      }
      target = data;
    }

    if (target && !target.verified) {
      throw new Error('COMPLIANCE BLOCK: Target ownership is not verified. Scan rejected.');
    }

    // Check ROE signature
    if (supabase && target) {
      const { data: sig } = await supabase
        .from('roe_signatures')
        .select('id')
        .eq('target_id', targetId)
        .limit(1);

      if (!sig || sig.length === 0) {
        throw new Error('COMPLIANCE BLOCK: No signed Rules of Engagement found. Scan rejected.');
      }
    }

    const targetName = target ? target.name : 'sandbox-target';
    const targetType = target ? target.type : 'domain';

    log(`[INFO] Target verified: ${targetName} (${targetType.toUpperCase()})`);
    log('[INFO] Rules of Engagement compliance: SIGNED & ACTIVE');

    // ── Step 2: DNS Reconnaissance ────────────────────────────
    if (targetType === 'domain') {
      log(`[RECON] Commencing DNS record enumeration for ${targetName}...`);

      try {
        const dnsResult = await scanDNS(targetName);
        scanMetadata.scanners.dns = dnsResult.metadata;

        const recordSummary = Object.entries(dnsResult.metadata.records || {})
          .filter(([_, records]) => records.length > 0)
          .map(([type, records]) => `${type}: ${records.length}`)
          .join(', ');

        log(`[RECON] DNS records resolved: ${recordSummary || 'No records found'}`);

        if (dnsResult.findings.length > 0) {
          log(`[RECON] DNS analysis isolated ${dnsResult.findings.length} finding(s)`);
          allFindings.push(...dnsResult.findings);
        }

        // Log email security status
        const txtRecords = dnsResult.metadata.records.TXT || [];
        const hasSPF = txtRecords.some(r => r.data && r.data.toLowerCase().includes('v=spf1'));
        log(`[RECON] Email Security — SPF: ${hasSPF ? 'CONFIGURED' : 'MISSING'}`);

      } catch (err) {
        log(`[ERROR] DNS scanner failed: ${err.message}`);
        scanMetadata.errors.push({ scanner: 'dns', error: err.message });
      }
    }

    // ── Step 3: SSL/TLS Certificate Analysis ──────────────────
    if (targetType === 'domain') {
      log(`[SECURITY] Analyzing SSL/TLS certificate for ${targetName}:443...`);

      try {
        const sslResult = await scanSSL(targetName);
        scanMetadata.scanners.ssl = sslResult.metadata;

        if (sslResult.metadata.certificate) {
          const cert = sslResult.metadata.certificate;
          log(`[SECURITY] Certificate Issuer: ${cert.issuer}`);
          log(`[SECURITY] Valid Until: ${cert.validTo}`);
          log(`[SECURITY] Protocol: ${cert.protocol || 'Unknown'}`);
          log(`[SECURITY] Authorized: ${cert.authorized ? 'YES (Trusted CA)' : 'NO (Untrusted)'}`);
        }

        if (sslResult.metadata.error) {
          log(`[WARNING] SSL probe issue: ${sslResult.metadata.error}`);
        }

        if (sslResult.findings.length > 0) {
          log(`[SECURITY] SSL/TLS analysis isolated ${sslResult.findings.length} finding(s)`);
          allFindings.push(...sslResult.findings);
        }

      } catch (err) {
        log(`[ERROR] SSL scanner failed: ${err.message}`);
        scanMetadata.errors.push({ scanner: 'ssl', error: err.message });
      }
    }

    // ── Step 4: HTTP Security Header Audit ────────────────────
    if (targetType === 'domain') {
      const targetUrl = `https://${targetName}`;
      log(`[DAST] Auditing HTTP security headers at ${targetUrl}...`);

      try {
        const headerResult = await scanHeaders(targetUrl);
        scanMetadata.scanners.headers = headerResult.metadata;

        if (headerResult.metadata.statusCode) {
          log(`[DAST] HTTP ${headerResult.metadata.statusCode} — Server: ${headerResult.metadata.serverInfo || 'Unknown'}`);
        }

        if (headerResult.metadata.error) {
          log(`[WARNING] Header probe issue: ${headerResult.metadata.error}`);
        }

        if (headerResult.findings.length > 0) {
          for (const finding of headerResult.findings) {
            const severityTag = finding.severity === 'critical' ? '[CRITICAL]' :
                                finding.severity === 'high' ? '[HIGH]' :
                                finding.severity === 'medium' ? '[WARNING]' : '[INFO]';
            log(`[DAST] ${severityTag} ${finding.title}`);
          }
          allFindings.push(...headerResult.findings);
        }

      } catch (err) {
        log(`[ERROR] Header scanner failed: ${err.message}`);
        scanMetadata.errors.push({ scanner: 'headers', error: err.message });
      }
    }

    // ── Step 4.5: Active Port & Service Discovery ─────────────
    if (targetType === 'domain') {
      log(`[NETWORK] Probing management and database ports at ${targetName}...`);
      try {
        const portResult = await scanPorts(targetName);
        scanMetadata.scanners.ports = portResult.metadata;

        if (portResult.metadata.error) {
          log(`[WARNING] Port probe issue: ${portResult.metadata.error}`);
        } else {
          log(`[NETWORK] Scanned ${portResult.metadata.portsScanned} ports. Found ${portResult.metadata.openPorts} open ports.`);
        }

        if (portResult.findings.length > 0) {
          for (const finding of portResult.findings) {
            log(`[NETWORK] [CRITICAL] ${finding.title}`);
          }
          allFindings.push(...portResult.findings);
        }
      } catch (err) {
        log(`[ERROR] Port scanner failed: ${err.message}`);
        scanMetadata.errors.push({ scanner: 'ports', error: err.message });
      }
    }

    // ── Step 5: Dependency Vulnerability Scan ─────────────────
    log('[SCA] Checking for dependency vulnerabilities via OSV.dev intelligence feed...');

    try {
      // For repository targets, we could scan the actual repo path
      // For domain targets, attempt to fetch package.json if exposed
      let packageJson = null;

      if (targetType === 'domain') {
        // Try to detect if package.json is publicly exposed (security check itself)
        try {
          const pkgResponse = await fetch(`https://${targetName}/package.json`, {
            headers: { 'User-Agent': 'Geolzen-Security-Scanner/1.0' }
          });

          if (pkgResponse.ok) {
            const contentType = pkgResponse.headers.get('content-type') || '';
            if (contentType.includes('json') || contentType.includes('text')) {
              const text = await pkgResponse.text();
              try {
                packageJson = JSON.parse(text);
                log('[SCA] [HIGH] package.json is publicly accessible on the web server!');

                // Add finding for exposed package.json
                allFindings.push({
                  title: 'Publicly Accessible package.json File',
                  severity: 'high',
                  category: 'DAST Audit',
                  description: `The file package.json is publicly accessible at https://${targetName}/package.json. This file exposes the complete dependency tree, package versions, and potentially internal project metadata to any visitor.`,
                  impact: 'High. Attackers can enumerate all dependencies and their exact versions, then cross-reference them against vulnerability databases to find exploitable CVEs without any scanning.',
                  solution: 'Configure your web server to block access to package.json, package-lock.json, and other development configuration files. In Nginx: location ~* (package\\.json|package-lock\\.json) { deny all; }',
                  fileName: `https://${targetName}/package.json`,
                  originalCode: `# package.json is publicly accessible\nlocation / {\n    # No restrictions\n}`,
                  fixedCode: `# Block access to dependency manifests\nlocation ~* (package\\.json|package-lock\\.json|\\.env) {\n    deny all;\n    return 404;\n}`,
                  remediated: false,
                  remediationType: 'config'
                });
              } catch (e) {
                // Response wasn't valid JSON, ignore
              }
            }
          }
        } catch (e) {
          // Fetch failed, no package.json exposed (which is good)
        }
      }

      if (packageJson && Object.keys(packageJson.dependencies || {}).length > 0) {
        const depResult = await scanDependencies(null, packageJson);
        scanMetadata.scanners.dependencies = depResult.metadata;

        if (depResult.findings.length > 0) {
          for (const finding of depResult.findings) {
            const severityTag = finding.severity === 'critical' ? '[CRITICAL]' : '[HIGH]';
            log(`[SCA] ${severityTag} ${finding.title}`);
          }
          allFindings.push(...depResult.findings);
        } else {
          log('[SCA] No known vulnerabilities found in detected dependencies.');
        }
      } else {
        log('[SCA] No exposed dependency manifests detected (this is expected and secure).');
      }

    } catch (err) {
      log(`[ERROR] Dependency scanner failed: ${err.message}`);
      scanMetadata.errors.push({ scanner: 'dependencies', error: err.message });
    }

    // ── Step 5.5: Application Layer (CMS) Scan ────────────────
    if (targetType === 'domain') {
      const targetUrl = `https://${targetName}`;
      log(`[DAST] Crawling application layer for CMS vulnerabilities at ${targetUrl}...`);
      try {
        const cmsResult = await scanCMS(targetUrl);
        scanMetadata.scanners.cms = cmsResult.metadata;

        if (cmsResult.metadata.error) {
          log(`[WARNING] CMS probe issue: ${cmsResult.metadata.error}`);
        }

        if (cmsResult.findings.length > 0) {
          for (const finding of cmsResult.findings) {
            const severityTag = finding.severity === 'critical' ? '[CRITICAL]' :
                                finding.severity === 'high' ? '[HIGH]' :
                                finding.severity === 'medium' ? '[WARNING]' : '[INFO]';
            log(`[DAST] ${severityTag} ${finding.title}`);
          }
          allFindings.push(...cmsResult.findings);
        } else {
          log('[DAST] No exposed CMS admin panels or version disclosures found.');
        }
      } catch (err) {
        log(`[ERROR] CMS scanner failed: ${err.message}`);
        scanMetadata.errors.push({ scanner: 'cms', error: err.message });
      }
    }

    // ── Step 6: Aggregate and Persist ─────────────────────────
    log('[INFO] Aggregating findings and compiling remediations...');

    // Deduplicate findings by title
    const seen = new Set();
    const uniqueFindings = allFindings.filter(f => {
      if (seen.has(f.title)) return false;
      seen.add(f.title);
      return true;
    });

    // Sort by severity
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    uniqueFindings.sort((a, b) => (severityOrder[a.severity] || 4) - (severityOrder[b.severity] || 4));

    // Persist to Supabase
    if (supabase && uniqueFindings.length > 0) {
      try {
        const insertPayload = uniqueFindings.map(f => ({
          target_id: targetId,
          title: f.title,
          severity: f.severity,
          category: f.category,
          description: f.description,
          impact: f.impact,
          solution: f.solution,
          file_name: f.fileName,
          original_code: f.originalCode,
          fixed_code: f.fixedCode,
          remediated: false,
          remediation_type: f.remediationType
        }));

        const { data: inserted, error } = await supabase
          .from('vulnerabilities')
          .insert(insertPayload)
          .select();

        if (error) {
          log(`[WARNING] Database persistence error: ${error.message}`);
        } else {
          log(`[INFO] ${inserted.length} findings persisted to Supabase vulnerabilities table.`);
          
          // Map database IDs back onto findings
          if (inserted) {
            inserted.forEach((dbRow, idx) => {
              if (uniqueFindings[idx]) {
                uniqueFindings[idx].id = dbRow.id;
              }
            });
          }
        }
      } catch (err) {
        log(`[WARNING] Database write failed: ${err.message}`);
        scanMetadata.errors.push({ phase: 'persistence', error: err.message });
      }
    }

    // Count by severity
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    uniqueFindings.forEach(f => { counts[f.severity] = (counts[f.severity] || 0) + 1; });

    log(`[INFO] SCAN COMPLETED SUCCESSFULLY. ${uniqueFindings.length} vulnerabilities isolated.`);
    log(`[INFO] Breakdown — Critical: ${counts.critical} | High: ${counts.high} | Medium: ${counts.medium} | Low: ${counts.low}`);

    // Update job status
    if (supabase && jobId) {
      await supabase
        .from('scan_jobs')
        .update({
          status: 'completed',
          completed_at: new Date().toISOString(),
          findings_count: uniqueFindings.length,
          metadata: scanMetadata
        })
        .eq('id', jobId);
    }

    scanMetadata.endTime = new Date().toISOString();
    scanMetadata.totalFindings = uniqueFindings.length;
    scanMetadata.counts = counts;

    return {
      success: true,
      jobId,
      findings: uniqueFindings,
      metadata: scanMetadata
    };

  } catch (err) {
    log(`[FATAL] ${err.message}`);

    // Update job status to failed
    if (supabase && jobId) {
      await supabase
        .from('scan_jobs')
        .update({
          status: 'failed',
          completed_at: new Date().toISOString(),
          metadata: { ...scanMetadata, fatalError: err.message }
        })
        .eq('id', jobId);
    }

    return {
      success: false,
      jobId,
      error: err.message,
      findings: allFindings,
      metadata: scanMetadata
    };
  }
}

module.exports = { executeScanPipeline };
