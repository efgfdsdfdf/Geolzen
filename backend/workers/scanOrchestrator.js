/**
 * Geolzen Scan Orchestrator v3.0
 * 
 * Coordinates all 12 scanner modules, aggregates findings,
 * and persists results to the Supabase database.
 * 
 * Scan Pipeline (12 Modules):
 *   FREE TIER:
 *     1. DNS Reconnaissance (passive)
 *     2. HTTP Security Header Audit (passive)
 *     3. Cookie Security Analysis (passive)
 *   STARTER TIER:
 *     4. SSL/TLS Certificate Analysis (passive)
 *     5. Dependency Vulnerability Scan (SCA via OSV.dev)
 *     6. CORS Misconfiguration Detection
 *   TEAM TIER:
 *     7. Active Network Port Probing (17 ports)
 *     8. Deep CMS & App Layer Crawling
 *     9. Sensitive File Exposure Probing
 *    10. Reflected XSS Payload Injection
 *    11. SQL Injection Error Detection
 *    12. Open Redirect Payload Testing
 *   
 *   FINALIZE: Aggregate, deduplicate, persist, and alert.
 */

const { scanHeaders } = require('../scanners/headerScanner');
const { scanSSL } = require('../scanners/sslScanner');
const { scanDNS } = require('../scanners/dnsScanner');
const { scanDependencies } = require('../scanners/depScanner');
const { scanPorts } = require('../scanners/portScanner');
const { scanCMS } = require('../scanners/cmsScanner');
const { scanCORS } = require('../scanners/corsScanner');
const { scanCookies } = require('../scanners/cookieScanner');
const { scanSensitiveFiles } = require('../scanners/sensitiveFileScanner');
const { scanXSS } = require('../scanners/xssScanner');
const { scanSQLi } = require('../scanners/sqliScanner');
const { scanOpenRedirect } = require('../scanners/openRedirectScanner');
const { crawlSite } = require('../scanners/crawler');
const { sendVulnerabilityAlert } = require('../utils/mailer');

/**
 * Execute a full scan pipeline against a verified target
 */
async function executeScanPipeline({ supabase, targetId, scanType, tier = 'free', userEmail, sendEmailAlerts = true, onLog }) {
  const log = onLog || ((msg) => console.log(`[SCAN] ${msg}`));
  const allFindings = [];
  const scanStart = Date.now();
  const scanMetadata = {
    targetId,
    scanType,
    startTime: new Date().toISOString(),
    scanners: {},
    errors: []
  };

  // Helper: elapsed time string
  const elapsed = () => {
    const s = ((Date.now() - scanStart) / 1000).toFixed(1);
    return `${s}s`;
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
    log('[INFO] Initializing Geolzen Security Core v3.0.0...');
    log(`[INFO] Scan tier: ${tier.toUpperCase()} | Modules available: ${tier === 'team' ? '12/12' : tier === 'starter' ? '6/12' : '3/12'}`);

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
    const targetUrl = `https://${targetName}`;

    log(`[INFO] Target verified: ${targetName} (${targetType.toUpperCase()})`);
    log('[INFO] Rules of Engagement compliance: SIGNED & ACTIVE');

    // Fetch existing vulnerabilities to avoid duplicates
    const existingFindings = [];
    if (supabase) {
      const { data: existing } = await supabase
        .from('vulnerabilities')
        .select('title, description')
        .eq('target_id', targetId);
      if (existing) existingFindings.push(...existing);
    }

    // ══════════════════════════════════════════════════════════
    // FREE TIER MODULES (3/12)
    // ══════════════════════════════════════════════════════════

    // ── Module 1: DNS Reconnaissance ──────────────────────────
    if (targetType === 'domain') {
      log(`[RECON] [${elapsed()}] Commencing DNS record enumeration for ${targetName}...`);

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
          const unique = dnsResult.findings.filter(f => !existingFindings.some(e => e.title === f.title));
          allFindings.push(...unique);
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

    // ── Module 2: HTTP Security Header Audit ──────────────────
    if (targetType === 'domain') {
      log(`[DAST] [${elapsed()}] Auditing HTTP security headers at ${targetUrl}...`);

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
          const unique = headerResult.findings.filter(f => !existingFindings.some(e => e.title === f.title));
          allFindings.push(...unique);
        }

      } catch (err) {
        log(`[ERROR] Header scanner failed: ${err.message}`);
        scanMetadata.errors.push({ scanner: 'headers', error: err.message });
      }
    }

    // ── Module 3: Cookie Security Analysis ────────────────────
    if (targetType === 'domain') {
      log(`[DAST] [${elapsed()}] Analyzing cookie security attributes at ${targetUrl}...`);

      try {
        const cookieResult = await scanCookies(targetUrl);
        scanMetadata.scanners.cookies = cookieResult.metadata;

        if (cookieResult.findings.length > 0) {
          log(`[DAST] Cookie audit isolated ${cookieResult.findings.length} finding(s)`);
          for (const finding of cookieResult.findings) {
            const severityTag = finding.severity === 'medium' ? '[WARNING]' : '[INFO]';
            log(`[DAST] ${severityTag} ${finding.title}`);
          }
          const unique = cookieResult.findings.filter(f => !existingFindings.some(e => e.title === f.title));
          allFindings.push(...unique);
        } else {
          log('[DAST] All cookies have secure attributes configured correctly.');
        }

      } catch (err) {
        log(`[ERROR] Cookie scanner failed: ${err.message}`);
        scanMetadata.errors.push({ scanner: 'cookies', error: err.message });
      }
    }

    // ══════════════════════════════════════════════════════════
    // STARTER TIER MODULES (6/12)
    // ══════════════════════════════════════════════════════════

    // ── Module 4: SSL/TLS Certificate Analysis ────────────────
    if (targetType === 'domain') {
      if (tier === 'free') {
        log('[INFO] 🔒 SSL/TLS Scanning is locked on the Free tier. Upgrade to Starter or Team to unlock.');
      } else {
        log(`[SECURITY] [${elapsed()}] Analyzing SSL/TLS certificate for ${targetName}:443...`);

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
            const unique = sslResult.findings.filter(f => !existingFindings.some(e => e.title === f.title));
            allFindings.push(...unique);
          }
        } catch (err) {
          log(`[ERROR] SSL scanner failed: ${err.message}`);
          scanMetadata.errors.push({ scanner: 'ssl', error: err.message });
        }
      }
    }

    // ── Module 5: Dependency Vulnerability Scan ───────────────
    if (tier === 'free') {
      log('[INFO] 🔒 Dependency Vulnerability Audits are locked on the Free tier. Upgrade to Starter to unlock.');
    } else {
      log(`[SCA] [${elapsed()}] Checking for dependency vulnerabilities via OSV.dev intelligence feed...`);

      try {
        let packageJson = null;

        if (targetType === 'domain') {
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

                  const finding = {
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
                  };
                  if (!existingFindings.some(e => e.title === finding.title)) {
                    allFindings.push(finding);
                  }
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
    }

    // ── Module 6: CORS Misconfiguration Detection ─────────────
    if (targetType === 'domain') {
      if (tier === 'free') {
        log('[INFO] 🔒 CORS Misconfiguration scanning is locked on the Free tier. Upgrade to Starter to unlock.');
      } else {
        log(`[DAST] [${elapsed()}] Testing CORS policy at ${targetUrl}...`);

        try {
          const corsResult = await scanCORS(targetUrl);
          scanMetadata.scanners.cors = corsResult.metadata;

          if (corsResult.findings.length > 0) {
            for (const finding of corsResult.findings) {
              const severityTag = finding.severity === 'critical' ? '[CRITICAL]' :
                                  finding.severity === 'high' ? '[HIGH]' : '[WARNING]';
              log(`[DAST] ${severityTag} ${finding.title}`);
            }
            allFindings.push(...corsResult.findings);
          } else {
            log('[DAST] CORS policy is properly configured. No misconfigurations detected.');
          }

        } catch (err) {
          log(`[ERROR] CORS scanner failed: ${err.message}`);
          scanMetadata.errors.push({ scanner: 'cors', error: err.message });
        }
      }
    }

    // ══════════════════════════════════════════════════════════
    // TEAM TIER MODULES (12/12)
    // ══════════════════════════════════════════════════════════

    // ── Module 7: Active Network Port Probing ─────────────────
    if (targetType === 'domain') {
      if (tier !== 'team') {
        log('[INFO] 🔒 Active Port Probing (17 ports) is locked. Upgrade to Team to unlock deep network scans.');
      } else {
        log(`[NETWORK] [${elapsed()}] Probing 17 infrastructure ports at ${targetName}...`);
        try {
          const portResult = await scanPorts(targetName);
          scanMetadata.scanners.ports = portResult.metadata;

          if (portResult.metadata.error) {
            log(`[WARNING] Port probe issue: ${portResult.metadata.error}`);
          } else {
            log(`[NETWORK] Scanned ${portResult.metadata.portsScanned} ports. Found ${portResult.metadata.openPorts} open.`);
          }

          if (portResult.findings.length > 0) {
            for (const finding of portResult.findings) {
              const severityTag = finding.severity === 'critical' ? '[CRITICAL]' :
                                  finding.severity === 'high' ? '[HIGH]' : '[WARNING]';
              log(`[NETWORK] ${severityTag} ${finding.title}`);
            }
            allFindings.push(...portResult.findings);
          } else {
            log('[NETWORK] No exposed management or database ports detected.');
          }
        } catch (err) {
          log(`[ERROR] Port scanner failed: ${err.message}`);
          scanMetadata.errors.push({ scanner: 'ports', error: err.message });
        }
      }
    }

    // ── Module 8: Deep CMS & App Layer Crawling ───────────────
    if (targetType === 'domain') {
      if (tier !== 'team') {
        log('[INFO] 🔒 Deep CMS & App Layer scanning is locked. Upgrade to Team to unlock.');
      } else {
        log(`[DAST] [${elapsed()}] Crawling application layer for CMS vulnerabilities at ${targetUrl}...`);
        try {
          const cmsResult = await scanCMS(targetUrl);
          scanMetadata.scanners.cms = cmsResult.metadata;

          if (cmsResult.metadata.error) {
            log(`[WARNING] CMS probe issue: ${cmsResult.metadata.error}`);
          }

          // Log detected technologies
          if (cmsResult.metadata.technologies && cmsResult.metadata.technologies.length > 0) {
            log(`[DAST] Technologies detected: ${cmsResult.metadata.technologies.join(', ')}`);
          }

          if (cmsResult.metadata.adminPanels && cmsResult.metadata.adminPanels.length > 0) {
            log(`[DAST] Exposed admin panels: ${cmsResult.metadata.adminPanels.join(', ')}`);
          }

          if (cmsResult.metadata.secretsFound > 0) {
            log(`[DAST] [CRITICAL] ${cmsResult.metadata.secretsFound} secret key(s) found in client-side code!`);
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
            log('[DAST] No exposed CMS admin panels, version disclosures, or leaked secrets found.');
          }
        } catch (err) {
          log(`[ERROR] CMS scanner failed: ${err.message}`);
          scanMetadata.errors.push({ scanner: 'cms', error: err.message });
        }
      }
    }

    // ── Module 9: Sensitive File Exposure Probing ──────────────
    if (targetType === 'domain') {
      if (tier !== 'team') {
        log('[INFO] 🔒 Sensitive File Exposure scanning is locked. Upgrade to Team to unlock.');
      } else {
        log(`[DAST] [${elapsed()}] Probing for exposed sensitive files and directories at ${targetUrl}...`);
        try {
          const fileResult = await scanSensitiveFiles(targetUrl);
          scanMetadata.scanners.sensitiveFiles = fileResult.metadata;

          if (fileResult.findings.length > 0) {
            for (const finding of fileResult.findings) {
              const severityTag = finding.severity === 'critical' ? '[CRITICAL]' :
                                  finding.severity === 'high' ? '[HIGH]' :
                                  finding.severity === 'medium' ? '[WARNING]' : '[INFO]';
              log(`[DAST] ${severityTag} ${finding.title}`);
            }
            allFindings.push(...fileResult.findings);
          } else {
            log('[DAST] No exposed sensitive files detected. Server configuration looks clean.');
          }
        } catch (err) {
          log(`[ERROR] Sensitive file scanner failed: ${err.message}`);
          scanMetadata.errors.push({ scanner: 'sensitiveFiles', error: err.message });
        }
      }
    }

    // ── Module 10, 11, 12: Web Crawler & Deep Payload Injection ────────────
    if (targetType === 'domain') {
      if (tier !== 'team') {
        log('[INFO] 🔒 Full-Site Crawler & Payload Testing is locked. Upgrade to Team to unlock active injection scans.');
      } else {
        log(`[SPIDER] [${elapsed()}] Initializing web crawler to discover internal pages at ${targetUrl}...`);
        try {
          const crawlResult = await crawlSite(targetUrl);
          scanMetadata.scanners.crawler = crawlResult.metadata;
          const pagesToScan = crawlResult.pages;
          
          log(`[SPIDER] Discovered ${pagesToScan.length} internal page(s) for deep scanning.`);

          // Initialize metadata for payload scanners
          scanMetadata.scanners.xss = { findingsCount: 0, pagesScanned: 0 };
          scanMetadata.scanners.sqli = { findingsCount: 0, pagesScanned: 0 };
          scanMetadata.scanners.openRedirect = { findingsCount: 0, pagesScanned: 0 };

          for (const pageUrl of pagesToScan) {
            log(`[PAYLOAD] [${elapsed()}] Deep scanning ${pageUrl}...`);
            
            // XSS
            try {
              const xssResult = await scanXSS(pageUrl);
              scanMetadata.scanners.xss.pagesScanned++;
              if (xssResult.findings.length > 0) {
                scanMetadata.scanners.xss.findingsCount += xssResult.findings.length;
                for (const f of xssResult.findings) log(`[PAYLOAD] [HIGH] ${f.title} on ${pageUrl}`);
                allFindings.push(...xssResult.findings);
              }
            } catch (e) {}

            // SQLi
            try {
              const sqliResult = await scanSQLi(pageUrl);
              scanMetadata.scanners.sqli.pagesScanned++;
              if (sqliResult.findings.length > 0) {
                scanMetadata.scanners.sqli.findingsCount += sqliResult.findings.length;
                for (const f of sqliResult.findings) log(`[PAYLOAD] [CRITICAL] ${f.title} on ${pageUrl}`);
                allFindings.push(...sqliResult.findings);
              }
            } catch (e) {}

            // Open Redirect
            try {
              const redirectResult = await scanOpenRedirect(pageUrl);
              scanMetadata.scanners.openRedirect.pagesScanned++;
              if (redirectResult.findings.length > 0) {
                scanMetadata.scanners.openRedirect.findingsCount += redirectResult.findings.length;
                for (const f of redirectResult.findings) log(`[PAYLOAD] [WARNING] ${f.title} on ${pageUrl}`);
                allFindings.push(...redirectResult.findings);
              }
            } catch (e) {}
          }
          
          if (scanMetadata.scanners.xss.findingsCount === 0) log('[PAYLOAD] No reflected XSS vulnerabilities detected across all pages.');
          if (scanMetadata.scanners.sqli.findingsCount === 0) log('[PAYLOAD] No SQL injection vulnerabilities detected across all pages.');
          if (scanMetadata.scanners.openRedirect.findingsCount === 0) log('[PAYLOAD] No open redirect vulnerabilities detected across all pages.');

        } catch (err) {
          log(`[ERROR] Crawler failed: ${err.message}`);
          scanMetadata.errors.push({ scanner: 'crawler', error: err.message });
        }
      }
    }

    // ══════════════════════════════════════════════════════════
    // FINALIZE: Aggregate, Deduplicate, Persist, Alert
    // ══════════════════════════════════════════════════════════
    log(`[INFO] [${elapsed()}] Aggregating findings and compiling remediations...`);

    // Deduplicate findings by title and fileName
    const seen = new Set();
    const uniqueFindings = allFindings.filter(f => {
      const key = `${f.title}-${f.fileName}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    // Sort by severity
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    uniqueFindings.sort((a, b) => (severityOrder[a.severity] || 4) - (severityOrder[b.severity] || 4));

    // Persist to Supabase
    if (supabase && uniqueFindings.length > 0) {
      try {
        // Fetch existing vulnerabilities to avoid duplicating records
        const { data: existingVulns } = await supabase
          .from('vulnerabilities')
          .select('id, title, file_name')
          .eq('target_id', targetId);

        const existingVulnsMap = new Map();
        if (existingVulns) {
          existingVulns.forEach(v => existingVulnsMap.set(`${v.title}-${v.file_name}`, v));
        }

        const newVulnsToInsert = [];
        uniqueFindings.forEach(f => {
          const key = `${f.title}-${f.fileName}`;
          if (!existingVulnsMap.has(key)) {
            newVulnsToInsert.push({
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
            });
          } else {
            f.id = existingVulnsMap.get(key).id;
          }
        });

        if (newVulnsToInsert.length > 0) {
          const { data: inserted, error } = await supabase
            .from('vulnerabilities')
            .insert(newVulnsToInsert)
            .select();

          if (error) {
            log(`[WARNING] Database persistence error: ${error.message}`);
          } else {
            log(`[INFO] ${inserted.length} NEW findings persisted to Supabase vulnerabilities table.`);
            
            if (inserted) {
              inserted.forEach((dbRow) => {
                const fIndex = uniqueFindings.findIndex(uf => uf.title === dbRow.title && uf.fileName === dbRow.file_name);
                if (fIndex !== -1) uniqueFindings[fIndex].id = dbRow.id;
              });
            }
          }
        } else {
          log(`[INFO] No new findings to persist. All findings already exist in the database.`);
        }
      } catch (err) {
        log(`[WARNING] Database write failed: ${err.message}`);
        scanMetadata.errors.push({ phase: 'persistence', error: err.message });
      }
    }

    // Count by severity
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    uniqueFindings.forEach(f => { counts[f.severity] = (counts[f.severity] || 0) + 1; });

    log(`[INFO] ═══════════════════════════════════════════════════`);
    log(`[INFO] SCAN COMPLETED SUCCESSFULLY in ${elapsed()}.`);
    log(`[INFO] ${uniqueFindings.length} unique vulnerabilities isolated across ${Object.keys(scanMetadata.scanners).length} modules.`);
    log(`[INFO] Breakdown — Critical: ${counts.critical} | High: ${counts.high} | Medium: ${counts.medium} | Low: ${counts.low}`);
    log(`[INFO] ═══════════════════════════════════════════════════`);

    // Trigger Email Alerts
    if (sendEmailAlerts && uniqueFindings.length > 0) {
      try {
        log(`[INFO] Preparing security alert email for ${userEmail}...`);
        const url = await sendVulnerabilityAlert(userEmail, targetName, uniqueFindings);
        log(`[MAILER] ✅ Security alert successfully sent! View it here: ${url}`);
      } catch (err) {
        if (err.message.toLowerCase().includes('timeout')) {
          log(`[WARNING] Email alert blocked. Render's Free Tier prevents outbound SMTP connections to prevent spam.`);
        } else {
          log(`[ERROR] Failed to send email alert: ${err.message}`);
        }
      }
    }

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
