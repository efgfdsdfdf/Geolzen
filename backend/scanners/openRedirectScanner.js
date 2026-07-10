/**
 * Open Redirect Scanner
 *
 * Tests for open redirect vulnerabilities by setting common redirect
 * parameters to a canary URL and checking whether the server issues
 * a redirect (via Location header or meta refresh) to that URL.
 *
 * Category: DAST Audit
 */

const EVIL_URL = 'https://evil-redirect.geolzen-probe.com';

const REDIRECT_PARAMETERS = [
  'url', 'redirect', 'next', 'return', 'returnUrl', 'redirect_uri',
  'continue', 'dest', 'destination', 'go', 'out', 'rurl', 'target',
];

const REDIRECT_STATUS_CODES = new Set([301, 302, 307, 308]);

const REQUEST_TIMEOUT_MS = 5000;

/**
 * Build a test URL by setting the given parameter to the evil redirect URL.
 */
function buildTestUrl(targetUrl, param) {
  const url = new URL(targetUrl);
  url.searchParams.set(param, EVIL_URL);
  return url.toString();
}

/**
 * Send a probe request without following redirects.
 * Returns { status, locationHeader, body } or null on error.
 */
async function sendProbe(testUrl) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const res = await fetch(testUrl, {
      method: 'GET',
      redirect: 'manual',
      signal: controller.signal,
      headers: {
        'User-Agent': 'Geolzen-Security-Scanner/1.0',
        'Accept': 'text/html,application/xhtml+xml,*/*',
      },
    });

    const body = await res.text();
    const locationHeader = res.headers.get('location') || '';

    return {
      status: res.status,
      locationHeader,
      body,
    };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Determine if the response indicates an open redirect to the evil URL.
 * Checks both the Location header and meta http-equiv="refresh" in the body.
 */
function detectRedirect(probeResult) {
  if (!probeResult) return { found: false, method: null };

  const { status, locationHeader, body } = probeResult;

  // Check Location header on redirect status codes
  if (REDIRECT_STATUS_CODES.has(status) && locationHeader.includes('evil-redirect.geolzen-probe.com')) {
    return { found: true, method: 'location-header' };
  }

  // Check for meta refresh redirect in the body
  const metaRefreshPattern = /meta\s+http-equiv\s*=\s*["']?refresh["']?[^>]*content\s*=\s*["'][^"']*evil-redirect\.geolzen-probe\.com/i;
  if (metaRefreshPattern.test(body)) {
    return { found: true, method: 'meta-refresh' };
  }

  return { found: false, method: null };
}

/**
 * Create a finding object for a confirmed open redirect.
 */
function createFinding(targetUrl, param, redirectMethod) {
  const methodLabel = redirectMethod === 'location-header'
    ? 'HTTP Location header redirect'
    : 'HTML meta refresh redirect';

  return {
    title: `Open Redirect via parameter "${param}"`,
    severity: 'medium',
    category: 'DAST Audit',
    description:
      `The parameter "${param}" at ${targetUrl} allows an attacker to redirect users to an arbitrary external URL. ` +
      `When set to ${EVIL_URL}, the server responded with a ${methodLabel} pointing to the attacker-controlled domain. ` +
      'This can be exploited for phishing attacks or credential theft.',
    impact:
      'An attacker can craft a legitimate-looking URL on the trusted domain that redirects victims ' +
      'to a phishing page, malware download, or credential harvesting site. This erodes user trust ' +
      'and can bypass email/content security filters that allow-list the trusted domain.',
    solution:
      'Validate redirect URLs against an allow-list of permitted destinations. ' +
      'Reject or ignore absolute URLs and URLs pointing to external domains. ' +
      'Use relative paths for internal redirects and verify the hostname matches the application domain.',
    fileName: new URL(targetUrl).pathname || '/',
    originalCode:
      `// Vulnerable: redirect destination taken directly from user input\n` +
      `const redirectTo = req.query.${param};\n` +
      `res.redirect(redirectTo);`,
    fixedCode:
      `// Fixed: validate redirect URL against allow-list\n` +
      `const redirectTo = req.query.${param};\n` +
      `const allowedHosts = ['example.com', 'www.example.com'];\n` +
      `try {\n` +
      `  const url = new URL(redirectTo, \`\${req.protocol}://\${req.get('host')}\`);\n` +
      `  if (!allowedHosts.includes(url.hostname)) {\n` +
      `    return res.redirect('/');\n` +
      `  }\n` +
      `  res.redirect(url.toString());\n` +
      `} catch {\n` +
      `  res.redirect('/');\n` +
      `}`,
    remediated: false,
    remediationType: 'code',
  };
}

/**
 * Scan a target URL for open redirect vulnerabilities.
 *
 * @param {string} targetUrl - The base URL to test.
 * @returns {{ findings: Array, metadata: Object }}
 */
async function scanOpenRedirect(targetUrl) {
  const findings = [];
  const testedParameters = [];
  const startTime = Date.now();
  let requestCount = 0;

  for (const param of REDIRECT_PARAMETERS) {
    const testUrl = buildTestUrl(targetUrl, param);
    testedParameters.push(param);
    requestCount++;

    const probeResult = await sendProbe(testUrl);
    const { found, method } = detectRedirect(probeResult);

    if (found) {
      findings.push(createFinding(targetUrl, param, method));
    }
  }

  const elapsedMs = Date.now() - startTime;

  return {
    findings,
    metadata: {
      scanner: 'openRedirectScanner',
      target: targetUrl,
      totalRequests: requestCount,
      totalFindings: findings.length,
      parametersChecked: REDIRECT_PARAMETERS.length,
      probeUrl: EVIL_URL,
      elapsedMs,
      testedParameters,
    },
  };
}

module.exports = { scanOpenRedirect };
