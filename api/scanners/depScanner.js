/**
 * Geolzen Dependency Vulnerability Scanner
 * 
 * Integrates with Trivy CLI (https://trivy.dev) for scanning
 * package manifests (package.json, requirements.txt, Gemfile, etc.)
 * against the National Vulnerability Database (NVD) and GitHub Advisory DB.
 * 
 * If Trivy is not installed, falls back to querying the OSV.dev
 * public vulnerability API directly.
 */

const { execFile } = require('child_process');
const path = require('path');

/**
 * Check if Trivy CLI is available on the system
 * @returns {Promise<boolean>}
 */
function isTrivyInstalled() {
  return new Promise((resolve) => {
    execFile('trivy', ['--version'], (error) => {
      resolve(!error);
    });
  });
}

/**
 * Run Trivy against a target filesystem path
 * @param {string} targetPath - Path to scan (directory or file)
 * @returns {Promise<object>}
 */
function runTrivy(targetPath) {
  return new Promise((resolve, reject) => {
    execFile('trivy', [
      'fs',
      '--format', 'json',
      '--severity', 'CRITICAL,HIGH,MEDIUM,LOW',
      '--scanners', 'vuln',
      '--quiet',
      targetPath
    ], { maxBuffer: 50 * 1024 * 1024, timeout: 120000 }, (error, stdout, stderr) => {
      if (error && !stdout) {
        return reject(new Error(`Trivy execution failed: ${stderr || error.message}`));
      }
      try {
        const results = JSON.parse(stdout);
        resolve(results);
      } catch (parseErr) {
        reject(new Error(`Failed to parse Trivy output: ${parseErr.message}`));
      }
    });
  });
}

/**
 * Parse Trivy JSON results into Geolzen vulnerability format
 * @param {object} trivyResults - Raw Trivy JSON output
 * @returns {Array} - Array of normalized vulnerability objects
 */
function parseTrivyResults(trivyResults) {
  const findings = [];

  if (!trivyResults || !trivyResults.Results) return findings;

  for (const result of trivyResults.Results) {
    const targetFile = result.Target || 'Unknown';

    if (!result.Vulnerabilities) continue;

    for (const vuln of result.Vulnerabilities) {
      const severity = (vuln.Severity || 'MEDIUM').toLowerCase();

      findings.push({
        title: `${vuln.VulnerabilityID}: ${vuln.Title || vuln.PkgName}`,
        severity: severity,
        category: 'Dependency SCA',
        description: vuln.Description || `Vulnerability ${vuln.VulnerabilityID} found in ${vuln.PkgName} version ${vuln.InstalledVersion}.`,
        impact: `${severity.charAt(0).toUpperCase() + severity.slice(1)}. ${vuln.PkgName}@${vuln.InstalledVersion} contains a known security vulnerability (${vuln.VulnerabilityID}). CVSS Score: ${vuln.CVSS?.nvd?.V3Score || vuln.CVSS?.ghsa?.V3Score || 'N/A'}.`,
        solution: vuln.FixedVersion
          ? `Upgrade ${vuln.PkgName} from version ${vuln.InstalledVersion} to ${vuln.FixedVersion}.`
          : `No fixed version is currently available for ${vuln.PkgName}. Monitor the advisory for updates.`,
        fileName: targetFile,
        originalCode: `"${vuln.PkgName}": "${vuln.InstalledVersion}"`,
        fixedCode: vuln.FixedVersion
          ? `"${vuln.PkgName}": "${vuln.FixedVersion}"`
          : `# No fix available yet — monitor ${vuln.VulnerabilityID}`,
        remediated: false,
        remediationType: 'pr',
        cveId: vuln.VulnerabilityID,
        references: vuln.References || []
      });
    }
  }

  return findings;
}

/**
 * Fallback: Query OSV.dev public API for package vulnerabilities
 * Works without Trivy installed. Checks npm packages from package.json.
 * @param {object} packageJson - Parsed package.json object
 * @returns {Promise<Array>} - Array of vulnerability findings
 */
async function queryOSV(packageJson) {
  const findings = [];
  const allDeps = {
    ...(packageJson.dependencies || {}),
    ...(packageJson.devDependencies || {})
  };

  for (const [pkgName, versionRange] of Object.entries(allDeps)) {
    // Clean version string (remove ^, ~, >= prefixes)
    const version = versionRange.replace(/[\^~>=<\s]/g, '');

    try {
      const response = await fetch('https://api.osv.dev/v1/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          package: { name: pkgName, ecosystem: 'npm' },
          version: version
        })
      });

      const data = await response.json();

      if (data.vulns && data.vulns.length > 0) {
        for (const vuln of data.vulns) {
          // Map OSV severity to Geolzen severity
          let severity = 'medium';
          const cvss = vuln.severity?.[0]?.score;
          if (cvss) {
            const score = parseFloat(cvss);
            if (score >= 9.0) severity = 'critical';
            else if (score >= 7.0) severity = 'high';
            else if (score >= 4.0) severity = 'medium';
            else severity = 'low';
          } else {
            // Fallback: check database_specific severity
            const dbSeverity = vuln.database_specific?.severity;
            if (dbSeverity) {
              severity = dbSeverity.toLowerCase();
            }
          }

          // Find the fixed version if available
          let fixedVersion = null;
          if (vuln.affected) {
            for (const affected of vuln.affected) {
              if (affected.package?.name === pkgName) {
                for (const range of (affected.ranges || [])) {
                  for (const event of (range.events || [])) {
                    if (event.fixed) {
                      fixedVersion = event.fixed;
                    }
                  }
                }
              }
            }
          }

          const vulnId = vuln.aliases?.find(a => a.startsWith('CVE-')) || vuln.id;

          findings.push({
            title: `${vulnId}: ${vuln.summary || pkgName}`,
            severity,
            category: 'Dependency SCA',
            description: vuln.details || vuln.summary || `Vulnerability ${vulnId} found in ${pkgName}@${version}.`,
            impact: `${severity.charAt(0).toUpperCase() + severity.slice(1)}. Package ${pkgName}@${version} contains ${vulnId}.`,
            solution: fixedVersion
              ? `Upgrade ${pkgName} from ${version} to ${fixedVersion}.`
              : `No fixed version available. Monitor ${vulnId} for updates.`,
            fileName: 'package.json',
            originalCode: `"${pkgName}": "${versionRange}"`,
            fixedCode: fixedVersion
              ? `"${pkgName}": "^${fixedVersion}"`
              : `# No fix available — monitor ${vulnId}`,
            remediated: false,
            remediationType: 'pr',
            cveId: vulnId,
            references: vuln.references?.map(r => r.url) || []
          });
        }
      }
    } catch (err) {
      // Skip packages that fail to query — don't block the scan
      console.error(`[DEP-SCANNER] Error querying OSV for ${pkgName}@${version}: ${err.message}`);
    }
  }

  return findings;
}

/**
 * Main entry point: scan dependencies for vulnerabilities
 * Tries Trivy first, falls back to OSV.dev API
 * @param {string} targetPath - Path to repository root (for Trivy)
 * @param {object|null} packageJson - Optional parsed package.json (for OSV fallback)
 * @returns {Promise<object>}
 */
async function scanDependencies(targetPath, packageJson) {
  const metadata = {
    scanner: 'geolzen-dep-scanner',
    startTime: new Date().toISOString(),
    method: null,
    targetPath
  };

  let findings = [];

  // Try Trivy first
  const trivyAvailable = await isTrivyInstalled();

  if (trivyAvailable && targetPath) {
    metadata.method = 'trivy';
    try {
      const results = await runTrivy(targetPath);
      findings = parseTrivyResults(results);
    } catch (err) {
      console.error(`[DEP-SCANNER] Trivy failed: ${err.message}. Falling back to OSV.dev API.`);
      metadata.method = 'osv-fallback';
      if (packageJson) {
        findings = await queryOSV(packageJson);
      }
    }
  } else if (packageJson) {
    // Fallback to OSV.dev public API
    metadata.method = 'osv-api';
    findings = await queryOSV(packageJson);
  } else {
    metadata.error = 'No Trivy installation found and no package.json provided for OSV fallback.';
  }

  metadata.endTime = new Date().toISOString();
  metadata.findingsCount = findings.length;

  return { findings, metadata };
}

module.exports = { scanDependencies, isTrivyInstalled, queryOSV };
