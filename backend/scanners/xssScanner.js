/**
 * Reflected XSS Scanner
 *
 * Tests for reflected cross-site scripting vulnerabilities by appending
 * safe, non-destructive canary payloads to common URL query parameters
 * and checking if they appear unencoded in the HTML response body.
 *
 * Category: DAST Audit
 */

const PAYLOADS = [
  '<geolzen-xss-probe>',
  '"><img src=x onerror=geolzen>',
  'javascript:geolzen',
  "'-alert(1)-'",
  '<svg/onload=geolzen>',
  '{{7*7}}',
];

const PARAMETER_NAMES = [
  'q', 'search', 'query', 'id', 'name', 'url', 'redirect',
  'page', 'callback', 'input', 'text', 'msg', 'error', 's',
];

const REQUEST_TIMEOUT_MS = 5000;
const MAX_PAYLOADS_PER_PARAM = 3;

/**
 * Build a test URL by appending a payload to a specific query parameter.
 * Preserves any existing query string on the target URL.
 */
function buildTestUrl(targetUrl, param, payload) {
  const url = new URL(targetUrl);
  url.searchParams.set(param, payload);
  return url.toString();
}

/**
 * Send a single probe request and return the response body text.
 * Returns null on any network / timeout error.
 */
async function sendProbe(testUrl) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const res = await fetch(testUrl, {
      method: 'GET',
      signal: controller.signal,
      headers: {
        'User-Agent': 'Geolzen-Security-Scanner/1.0',
        'Accept': 'text/html,application/xhtml+xml,*/*',
      },
    });
    return await res.text();
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Create a finding object for a confirmed reflected XSS.
 */
function createFinding(targetUrl, param, payload) {
  return {
    title: `Reflected XSS via parameter "${param}"`,
    severity: 'high',
    category: 'DAST Audit',
    description:
      `The parameter "${param}" reflects the payload ${payload} unencoded in the HTTP response body at ${targetUrl}. ` +
      'An attacker can craft a malicious URL that executes arbitrary JavaScript in a victim\'s browser when they visit the link.',
    impact:
      'An attacker can steal session cookies, hijack user accounts, deface the page, ' +
      'or redirect victims to malicious sites by sending them a crafted URL.',
    solution:
      'Sanitize and HTML-encode all user-supplied input before reflecting it in the page. ' +
      'Use Content-Security-Policy headers to restrict inline script execution. ' +
      'Adopt a templating engine that auto-escapes output by default.',
    fileName: new URL(targetUrl).pathname || '/',
    originalCode: `// User input reflected without encoding\nres.send(\`Result: \${req.query.${param}}\`);`,
    fixedCode: `// HTML-encode user input before reflecting\nconst escapeHtml = require('escape-html');\nres.send(\`Result: \${escapeHtml(req.query.${param})}\`);`,
    remediated: false,
    remediationType: 'code',
  };
}

/**
 * Scan a target URL for reflected XSS vulnerabilities.
 *
 * @param {string} targetUrl - The base URL to test.
 * @returns {{ findings: Array, metadata: Object }}
 */
async function scanXSS(targetUrl) {
  const findings = [];
  const testedCombinations = [];
  const vulnerableParams = new Set();
  const startTime = Date.now();
  let requestCount = 0;

  for (const param of PARAMETER_NAMES) {
    // Deduplicate — skip if this parameter already produced a finding
    if (vulnerableParams.has(param)) continue;

    // Only test up to MAX_PAYLOADS_PER_PARAM payloads per parameter
    const payloadsToTest = PAYLOADS.slice(0, MAX_PAYLOADS_PER_PARAM);

    for (const payload of payloadsToTest) {
      if (vulnerableParams.has(param)) break;

      const testUrl = buildTestUrl(targetUrl, param, payload);
      testedCombinations.push({ param, payload });
      requestCount++;

      const body = await sendProbe(testUrl);

      if (body && body.includes(payload)) {
        findings.push(createFinding(targetUrl, param, payload));
        vulnerableParams.add(param);
      }
    }
  }

  const elapsedMs = Date.now() - startTime;

  return {
    findings,
    metadata: {
      scanner: 'xssScanner',
      target: targetUrl,
      totalRequests: requestCount,
      totalFindings: findings.length,
      parametersChecked: PARAMETER_NAMES.length,
      payloadsPerParameter: MAX_PAYLOADS_PER_PARAM,
      elapsedMs,
      testedCombinations,
    },
  };
}

module.exports = { scanXSS };
