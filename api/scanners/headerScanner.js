/**
 * Geolzen HTTP Security Header Scanner
 * 
 * Performs passive analysis of HTTP response headers to identify
 * missing or misconfigured security directives. This is equivalent
 * to what a web browser does when loading a page.
 */

const SECURITY_HEADERS = [
  {
    name: 'Content-Security-Policy',
    severity: 'high',
    category: 'DAST Audit',
    missingTitle: 'Missing Content Security Policy (CSP) Header',
    missingDescription: 'The application does not return a Content-Security-Policy header. CSP instructs browsers which dynamic resources are permitted to load, providing a strong defense against Cross-Site Scripting (XSS), clickjacking, and code injection attacks.',
    missingImpact: 'High. Without CSP, attackers can inject malicious scripts into web pages viewed by other users, steal session tokens, or redirect users to phishing pages.',
    missingSolution: 'Configure your web server or application to return a Content-Security-Policy header. Start with a restrictive policy like: default-src \'self\'; script-src \'self\'; style-src \'self\' \'unsafe-inline\'; img-src \'self\' data:; frame-ancestors \'none\';',
    validate: (value) => {
      const issues = [];
      if (value.includes("'unsafe-eval'")) {
        issues.push("Policy allows 'unsafe-eval' which enables dynamic code execution via eval().");
      }
      if (value.includes('*') && !value.includes('*.')) {
        issues.push("Policy uses wildcard (*) source which negates CSP protection.");
      }
      return issues;
    }
  },
  {
    name: 'Strict-Transport-Security',
    severity: 'high',
    category: 'DAST Audit',
    missingTitle: 'Missing HTTP Strict Transport Security (HSTS) Header',
    missingDescription: 'The server does not enforce HTTPS via the Strict-Transport-Security header. Without HSTS, browsers may allow initial HTTP connections before redirecting to HTTPS, creating a window for man-in-the-middle (MITM) attacks.',
    missingImpact: 'High. Attackers on the same network can intercept the initial HTTP request and downgrade the connection, capturing credentials or injecting malicious content.',
    missingSolution: 'Add the Strict-Transport-Security header with a minimum max-age of 31536000 seconds (1 year). Include the includeSubDomains directive if all subdomains also support HTTPS.',
    validate: (value) => {
      const issues = [];
      const maxAgeMatch = value.match(/max-age=(\d+)/);
      if (maxAgeMatch && parseInt(maxAgeMatch[1]) < 31536000) {
        issues.push(`HSTS max-age is ${maxAgeMatch[1]} seconds, which is below the recommended 31536000 (1 year).`);
      }
      return issues;
    }
  },
  {
    name: 'X-Frame-Options',
    severity: 'medium',
    category: 'DAST Audit',
    missingTitle: 'Missing X-Frame-Options Header',
    missingDescription: 'The application does not set the X-Frame-Options header. This header controls whether a page can be embedded in an iframe, preventing clickjacking attacks where attackers overlay invisible frames to trick users into clicking unintended elements.',
    missingImpact: 'Medium. Attackers can embed the target page in a transparent iframe and trick authenticated users into performing unintended actions such as changing account settings or transferring funds.',
    missingSolution: 'Set the X-Frame-Options header to DENY (to prevent all framing) or SAMEORIGIN (to allow framing only from the same domain).',
    validate: (value) => {
      const issues = [];
      const upper = value.toUpperCase();
      if (upper !== 'DENY' && upper !== 'SAMEORIGIN') {
        issues.push(`X-Frame-Options value "${value}" is not a standard directive. Use DENY or SAMEORIGIN.`);
      }
      return issues;
    }
  },
  {
    name: 'X-Content-Type-Options',
    severity: 'medium',
    category: 'DAST Audit',
    missingTitle: 'Missing X-Content-Type-Options Header',
    missingDescription: 'The server does not set the X-Content-Type-Options header. Without this header, browsers may perform MIME-type sniffing, potentially interpreting uploaded files as executable scripts.',
    missingImpact: 'Medium. Attackers can upload files with misleading extensions that browsers interpret as JavaScript or HTML, leading to stored XSS or drive-by download attacks.',
    missingSolution: 'Set the X-Content-Type-Options header to "nosniff" to prevent browsers from MIME-sniffing the response content type.',
    validate: (value) => {
      const issues = [];
      if (value.toLowerCase() !== 'nosniff') {
        issues.push(`X-Content-Type-Options value "${value}" is invalid. The only valid value is "nosniff".`);
      }
      return issues;
    }
  },
  {
    name: 'Referrer-Policy',
    severity: 'low',
    category: 'DAST Audit',
    missingTitle: 'Missing Referrer-Policy Header',
    missingDescription: 'The application does not specify a Referrer-Policy header. Without this header, browsers send the full URL (including query parameters that may contain tokens or session IDs) as the Referer header when navigating to external sites.',
    missingImpact: 'Low. Sensitive information in URL query parameters (such as password reset tokens, session IDs, or API keys) may be leaked to third-party websites via the Referer header.',
    missingSolution: 'Set the Referrer-Policy header to "strict-origin-when-cross-origin" or "no-referrer" to control what referrer information is sent.',
    validate: (value) => {
      const valid = ['no-referrer', 'no-referrer-when-downgrade', 'origin', 'origin-when-cross-origin', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin', 'unsafe-url'];
      const issues = [];
      if (!valid.includes(value.toLowerCase())) {
        issues.push(`Referrer-Policy value "${value}" is not a recognized directive.`);
      }
      if (value.toLowerCase() === 'unsafe-url') {
        issues.push("Referrer-Policy is set to 'unsafe-url' which leaks the full URL including path and query parameters to all destinations.");
      }
      return issues;
    }
  },
  {
    name: 'Permissions-Policy',
    severity: 'low',
    category: 'DAST Audit',
    missingTitle: 'Missing Permissions-Policy Header',
    missingDescription: 'The application does not set a Permissions-Policy (formerly Feature-Policy) header. This header controls access to browser features like geolocation, camera, microphone, and payment APIs.',
    missingImpact: 'Low. Without a Permissions-Policy, embedded iframes or injected scripts could access sensitive browser APIs like the camera, microphone, or geolocation without restriction.',
    missingSolution: 'Set the Permissions-Policy header to disable unused browser features. Example: Permissions-Policy: camera=(), microphone=(), geolocation=()',
    validate: () => []
  }
];

/**
 * Scan a target URL for HTTP security header compliance
 * @param {string} targetUrl - The full URL to scan (e.g., https://example.com)
 * @returns {Promise<object>} - Scan results containing findings array and metadata
 */
async function scanHeaders(targetUrl) {
  const findings = [];
  const metadata = {
    scanner: 'geolzen-header-scanner',
    targetUrl,
    startTime: new Date().toISOString(),
    headersFound: {},
    serverInfo: null
  };

  try {
    // Make a standard HTTP GET request (same as any web browser)
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000);

    const response = await fetch(targetUrl, {
      method: 'GET',
      redirect: 'follow',
      signal: controller.signal,
      headers: {
        'User-Agent': 'Geolzen-Security-Scanner/1.0 (Authorized Vulnerability Assessment)'
      }
    });

    clearTimeout(timeout);

    metadata.statusCode = response.status;
    metadata.finalUrl = response.url;
    metadata.serverInfo = response.headers.get('server') || 'Not disclosed';

    // Collect all response headers for reference
    response.headers.forEach((value, name) => {
      metadata.headersFound[name] = value;
    });

    // Evaluate each security header
    for (const headerDef of SECURITY_HEADERS) {
      const headerValue = response.headers.get(headerDef.name);

      if (!headerValue) {
        // Header is completely missing
        findings.push({
          title: headerDef.missingTitle,
          severity: headerDef.severity,
          category: headerDef.category,
          description: headerDef.missingDescription,
          impact: headerDef.missingImpact,
          solution: headerDef.missingSolution,
          fileName: `Response Headers: ${targetUrl}`,
          originalCode: `# HTTP Response Headers\n# ${headerDef.name}: [NOT SET]`,
          fixedCode: `# HTTP Response Headers\n${headerDef.name}: ${headerDef.missingSolution.split(': ').slice(1).join(': ') || 'See solution'}`,
          remediated: false,
          remediationType: 'config'
        });
      } else {
        // Header exists - validate its configuration
        const issues = headerDef.validate(headerValue);
        for (const issue of issues) {
          findings.push({
            title: `Misconfigured ${headerDef.name} Header`,
            severity: headerDef.severity === 'high' ? 'medium' : 'low',
            category: headerDef.category,
            description: `The ${headerDef.name} header is present but misconfigured. ${issue}`,
            impact: `Reduced effectiveness of ${headerDef.name} security control.`,
            solution: `Review and correct the ${headerDef.name} header value. Current value: "${headerValue}".`,
            fileName: `Response Headers: ${targetUrl}`,
            originalCode: `${headerDef.name}: ${headerValue}`,
            fixedCode: `# Refer to solution guidance for correct value`,
            remediated: false,
            remediationType: 'config'
          });
        }
      }
    }

    // Check for information disclosure headers
    const serverHeader = response.headers.get('server');
    if (serverHeader && /\d+\.\d+/.test(serverHeader)) {
      findings.push({
        title: 'Server Version Disclosure in HTTP Headers',
        severity: 'low',
        category: 'DAST Audit',
        description: `The Server header discloses specific version information: "${serverHeader}". Exposing server software and version numbers assists attackers in identifying known vulnerabilities for that specific version.`,
        impact: 'Low. Version disclosure enables attackers to narrow their attack surface and target version-specific exploits.',
        solution: 'Configure the web server to suppress or generalize the Server header. For Nginx: server_tokens off; For Apache: ServerTokens Prod',
        fileName: `Response Headers: ${targetUrl}`,
        originalCode: `Server: ${serverHeader}`,
        fixedCode: `# Server header suppressed or generalized\nServer: Geolzen`,
        remediated: false,
        remediationType: 'config'
      });
    }

    const poweredBy = response.headers.get('x-powered-by');
    if (poweredBy) {
      findings.push({
        title: 'Technology Stack Disclosure via X-Powered-By Header',
        severity: 'low',
        category: 'DAST Audit',
        description: `The X-Powered-By header reveals the backend technology stack: "${poweredBy}". This information helps attackers identify framework-specific vulnerabilities.`,
        impact: 'Low. Technology stack disclosure narrows the attack surface for targeted exploits.',
        solution: 'Remove the X-Powered-By header. In Express.js: app.disable("x-powered-by"); In PHP: expose_php = Off',
        fileName: `Response Headers: ${targetUrl}`,
        originalCode: `X-Powered-By: ${poweredBy}`,
        fixedCode: `# X-Powered-By header removed`,
        remediated: false,
        remediationType: 'config'
      });
    }

  } catch (err) {
    if (err.name === 'AbortError') {
      metadata.error = 'Connection timed out after 15 seconds';
    } else {
      metadata.error = err.message;
    }
  }

  metadata.endTime = new Date().toISOString();
  metadata.findingsCount = findings.length;

  return { findings, metadata };
}

module.exports = { scanHeaders };
