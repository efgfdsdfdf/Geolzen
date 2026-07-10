/**
 * Geolzen Sensitive File Exposure Scanner
 * 
 * Probes for commonly exposed configuration files, backups, and metadata
 * by sending GET requests and verifying HTTP 200 responses with legitimate content.
 */

const SENSITIVE_FILES = [
  { path: '/.env', severity: 'critical', description: 'Environment variables file exposed. May contain database passwords, API keys, and third-party service credentials in plaintext.' },
  { path: '/.git/config', severity: 'high', description: 'Git configuration file exposed, potentially revealing repository URLs, branch information, and stored credentials.' },
  { path: '/.git/HEAD', severity: 'high', description: 'Git HEAD file exposed, confirming the entire .git directory is publicly accessible. Attackers can reconstruct source code.' },
  { path: '/.htaccess', severity: 'medium', description: 'Apache configuration file exposed. May reveal URL rewrite rules, authentication mechanisms, and directory restrictions.' },
  { path: '/web.config', severity: 'medium', description: 'IIS configuration file exposed. May contain connection strings, authentication settings, and custom error configurations.' },
  { path: '/wp-config.php', severity: 'critical', description: 'WordPress configuration file exposed with database credentials, authentication keys, and salts in plaintext.' },
  { path: '/phpinfo.php', severity: 'high', description: 'PHP information page exposed, disclosing full server configuration, loaded modules, environment variables, and file paths.' },
  { path: '/composer.json', severity: 'medium', description: 'PHP dependency manifest exposed. Reveals application dependencies and versions that may have known vulnerabilities.' },
  { path: '/Gemfile', severity: 'medium', description: 'Ruby dependency manifest exposed. Reveals application stack and gem versions that could be targeted.' },
  { path: '/requirements.txt', severity: 'medium', description: 'Python dependency manifest exposed. Reveals Python packages and versions in use.' },
  { path: '/.dockerignore', severity: 'low', description: 'Docker ignore file exposed. Reveals project structure and files excluded from Docker builds.' },
  { path: '/Dockerfile', severity: 'high', description: 'Dockerfile exposed. May contain hardcoded secrets, base image versions, and internal build instructions.' },
  { path: '/docker-compose.yml', severity: 'high', description: 'Docker Compose configuration exposed. Often contains database passwords, service architecture, and internal network topology.' },
  { path: '/.aws/credentials', severity: 'critical', description: 'AWS credentials file exposed. Contains access key IDs and secret access keys granting direct access to AWS resources.' },
  { path: '/server-status', severity: 'medium', description: 'Apache server-status page exposed, revealing active connections, request URIs, client IPs, and server load metrics.' },
  { path: '/elmah.axd', severity: 'high', description: '.NET ELMAH error log handler exposed. Reveals full stack traces, request details, and internal application errors.' },
  { path: '/.svn/entries', severity: 'high', description: 'SVN metadata file exposed. Reveals repository structure, revision history, and potentially source code.' },
  { path: '/backup.sql', severity: 'critical', description: 'Database backup file publicly accessible. Contains full database schema and data including user credentials.' },
  { path: '/db.sql', severity: 'critical', description: 'Database dump file publicly accessible. Contains full database contents including sensitive records.' },
  { path: '/debug.log', severity: 'medium', description: 'Debug log file exposed. May contain stack traces, internal paths, query parameters, and sensitive runtime data.' }
];

const SUSPICIOUS_KEYWORDS = [
  'admin', 'secret', 'backup', 'staging', 'internal',
  'private', 'api', 'dashboard', 'debug', 'test', 'dev'
];

/**
 * Verify that a response contains legitimate content (not a custom 404 page)
 * @param {Response} response - Fetch response object
 * @param {string} body - Response body text
 * @returns {boolean} True if the response appears to be legitimate
 */
function isLegitimateResponse(response, body) {
  const contentType = response.headers.get('content-type') || '';

  // Check if Content-Type suggests real file content (not an HTML error page for non-HTML files)
  const isHtmlResponse = contentType.includes('text/html');
  const isExpectedHtml = response.url.includes('.php') || 
                         response.url.includes('.axd') ||
                         response.url.includes('server-status');

  // If we get HTML back for a non-HTML file, it's likely a custom 404
  if (isHtmlResponse && !isExpectedHtml) {
    return false;
  }

  // Response body must be more than 10 bytes to avoid empty/stub pages
  if (!body || body.length <= 10) {
    return false;
  }

  return true;
}

/**
 * Check if a single sensitive file is exposed
 * @param {string} baseUrl - Target base URL
 * @param {object} fileInfo - File path and metadata
 * @returns {Promise<object|null>} Finding object or null if not exposed
 */
async function checkFile(baseUrl, fileInfo) {
  try {
    const url = `${baseUrl}${fileInfo.path}`;
    const response = await fetch(url, {
      method: 'GET',
      redirect: 'follow',
      headers: {
        'User-Agent': 'Geolzen-SecurityScanner/1.0'
      },
      signal: AbortSignal.timeout(8000)
    });

    if (response.status !== 200) {
      return null;
    }

    const body = await response.text();

    if (!isLegitimateResponse(response, body)) {
      return null;
    }

    return {
      title: `Sensitive File Exposed: ${fileInfo.path}`,
      severity: fileInfo.severity,
      category: 'DAST Audit',
      description: fileInfo.description,
      impact: `The file ${fileInfo.path} is publicly accessible, allowing attackers to harvest credentials, configuration details, or internal application data.`,
      solution: `Remove or restrict access to ${fileInfo.path}. Configure your web server to deny requests to sensitive files and directories.`,
      fileName: fileInfo.path,
      originalCode: `# Current Web Server Config\n# No access restriction for ${fileInfo.path}\nLocation ${fileInfo.path} {\n  # Publicly accessible\n}`,
      fixedCode: `# Recommended Web Server Config\nLocation ${fileInfo.path} {\n  deny all;\n  return 404;\n}`,
      remediated: false,
      remediationType: 'config'
    };
  } catch {
    // Network error, timeout, etc. — file is not accessible
    return null;
  }
}

/**
 * Fetch and parse robots.txt for suspicious Disallow entries
 * @param {string} baseUrl - Target base URL
 * @returns {Promise<object[]>} Array of findings from robots.txt analysis
 */
async function checkRobotsTxt(baseUrl) {
  const findings = [];

  try {
    const response = await fetch(`${baseUrl}/robots.txt`, {
      method: 'GET',
      redirect: 'follow',
      headers: {
        'User-Agent': 'Geolzen-SecurityScanner/1.0'
      },
      signal: AbortSignal.timeout(8000)
    });

    if (response.status !== 200) {
      return findings;
    }

    const body = await response.text();

    if (!body || body.length <= 10) {
      return findings;
    }

    const lines = body.split('\n');
    const disallowPaths = [];

    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed.toLowerCase().startsWith('disallow:')) {
        const path = trimmed.substring('disallow:'.length).trim();
        if (path) {
          disallowPaths.push(path);
        }
      }
    }

    for (const path of disallowPaths) {
      const lowerPath = path.toLowerCase();
      const matchedKeywords = SUSPICIOUS_KEYWORDS.filter(keyword => lowerPath.includes(keyword));

      if (matchedKeywords.length > 0) {
        findings.push({
          title: `Suspicious Path in robots.txt: ${path}`,
          severity: 'medium',
          category: 'DAST Audit',
          description: `The robots.txt file contains a Disallow entry for "${path}" which references sensitive keywords: ${matchedKeywords.join(', ')}. While robots.txt prevents search engine crawling, it publicly advertises hidden paths to attackers.`,
          impact: `Attackers routinely check robots.txt for hidden administrative panels, backup locations, and internal tools. The path "${path}" may lead to sensitive functionality.`,
          solution: 'Do not rely on robots.txt for security. Protect sensitive paths with authentication, IP restrictions, and proper access controls instead of merely hiding them from crawlers.',
          fileName: '/robots.txt',
          originalCode: `# robots.txt\nDisallow: ${path}`,
          fixedCode: `# robots.txt — Remove sensitive paths\n# Disallow: ${path}  ← REMOVED\n\n# Instead, protect this path with authentication:\n# Location ${path} {\n#   auth_basic "Restricted";\n#   deny all;\n# }`,
          remediated: false,
          remediationType: 'config'
        });
      }
    }
  } catch {
    // robots.txt not accessible — skip
  }

  return findings;
}

/**
 * Scan a target URL for exposed sensitive files
 * @param {string} targetUrl - Full URL of the target (e.g. https://example.com)
 * @returns {Promise<object>} Scan results with findings and metadata
 */
async function scanSensitiveFiles(targetUrl) {
  // Normalize base URL — remove trailing slash
  const baseUrl = targetUrl.replace(/\/+$/, '');

  const findings = [];
  const metadata = {
    target: baseUrl,
    startTime: new Date().toISOString(),
    filesChecked: SENSITIVE_FILES.length,
    exposedFiles: 0,
    robotsTxtFindings: 0,
    error: null
  };

  try {
    // Run all file checks and robots.txt scan concurrently
    const [fileResults, robotsFindings] = await Promise.all([
      Promise.all(SENSITIVE_FILES.map(fileInfo => checkFile(baseUrl, fileInfo))),
      checkRobotsTxt(baseUrl)
    ]);

    // Collect file exposure findings
    for (const result of fileResults) {
      if (result !== null) {
        metadata.exposedFiles++;
        findings.push(result);
      }
    }

    // Collect robots.txt findings
    metadata.robotsTxtFindings = robotsFindings.length;
    findings.push(...robotsFindings);
  } catch (err) {
    metadata.error = err.message;
  }

  metadata.endTime = new Date().toISOString();
  return { findings, metadata };
}

module.exports = { scanSensitiveFiles };
