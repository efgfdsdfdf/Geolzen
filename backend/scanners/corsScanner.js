/**
 * CORS Misconfiguration Scanner
 * Detects insecure Cross-Origin Resource Sharing configurations
 * including reflected origins, wildcard CORS, credentials leakage,
 * and null origin acceptance.
 */

const USER_AGENT = 'Geolzen-Security-Scanner/1.0 (Authorized Vulnerability Assessment)';
const TIMEOUT_MS = 8000;

/**
 * Sends a request with a custom Origin header and returns the response headers.
 * @param {string} targetUrl - The URL to test
 * @param {string|null} origin - The Origin header value to send
 * @returns {Promise<{headers: Headers, status: number}|null>}
 */
async function sendCORSProbe(targetUrl, origin) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const headers = {
      'User-Agent': USER_AGENT,
    };

    if (origin !== undefined) {
      headers['Origin'] = origin;
    }

    const response = await fetch(targetUrl, {
      method: 'GET',
      headers,
      signal: controller.signal,
      redirect: 'follow',
    });

    clearTimeout(timeoutId);
    return { headers: response.headers, status: response.status };
  } catch (error) {
    clearTimeout(timeoutId);
    if (error.name === 'AbortError') {
      console.error(`[CORS Scanner] Request to ${targetUrl} timed out after ${TIMEOUT_MS}ms`);
    } else {
      console.error(`[CORS Scanner] Request failed for ${targetUrl}: ${error.message}`);
    }
    return null;
  }
}

/**
 * Scans a target URL for CORS misconfigurations.
 * @param {string} targetUrl - The URL to scan
 * @returns {Promise<{findings: Array, metadata: Object}>}
 */
async function scanCORS(targetUrl) {
  const findings = [];
  const startTime = Date.now();

  // --- Probe 1: Reflected Origin ---
  const evilOrigin = 'https://evil-attacker.com';
  const reflectedProbe = await sendCORSProbe(targetUrl, evilOrigin);

  if (reflectedProbe) {
    const acao = reflectedProbe.headers.get('access-control-allow-origin');
    const acac = reflectedProbe.headers.get('access-control-allow-credentials');
    const credentialsEnabled = acac && acac.trim().toLowerCase() === 'true';

    // Check: Reflected Origin
    if (acao && acao.trim() === evilOrigin) {
      findings.push({
        title: 'CORS Reflected Origin Vulnerability',
        severity: credentialsEnabled ? 'critical' : 'high',
        category: 'DAST Audit',
        description:
          `The server reflects the arbitrary Origin header value "${evilOrigin}" in the Access-Control-Allow-Origin response header. ` +
          `This means any external domain can make cross-origin requests to this endpoint and read the responses.` +
          (credentialsEnabled
            ? ' Combined with Access-Control-Allow-Credentials: true, this allows attackers to steal authenticated user data.'
            : ''),
        impact:
          'An attacker can craft a malicious webpage that makes authenticated requests to this endpoint and reads sensitive response data, ' +
          'potentially leading to full account takeover, data exfiltration, or unauthorized actions on behalf of the victim.',
        solution:
          'Implement a strict allowlist of trusted origins and validate the Origin header against it before reflecting it in the response. ' +
          'Never blindly reflect the Origin header. Use a server-side allowlist such as: ' +
          "const ALLOWED_ORIGINS = ['https://yourdomain.com', 'https://app.yourdomain.com'].",
        fileName: 'Server CORS Configuration',
        originalCode:
          `Access-Control-Allow-Origin: ${evilOrigin}\n` +
          (credentialsEnabled ? 'Access-Control-Allow-Credentials: true' : ''),
        fixedCode:
          'Access-Control-Allow-Origin: https://yourdomain.com\n' +
          'Access-Control-Allow-Credentials: true\n' +
          '// Validate Origin against a strict allowlist before reflecting',
        remediated: false,
        remediationType: 'config',
      });
    }

    // Check: Wildcard CORS
    if (acao && acao.trim() === '*') {
      const wildcardSeverity = credentialsEnabled ? 'critical' : 'medium';
      findings.push({
        title: 'CORS Wildcard Access-Control-Allow-Origin',
        severity: wildcardSeverity,
        category: 'DAST Audit',
        description:
          'The server responds with Access-Control-Allow-Origin: *, allowing any website to make cross-origin requests and read the responses.' +
          (credentialsEnabled
            ? ' CRITICAL: Access-Control-Allow-Credentials is also set to true, which browsers typically block with wildcards, ' +
              'but misconfigured proxies or older browsers may not enforce this restriction.'
            : ''),
        impact:
          'Any website can read response data from this endpoint. If the endpoint returns sensitive or user-specific information, ' +
          'it can be exfiltrated by an attacker-controlled page visited by the victim.',
        solution:
          'Replace the wildcard (*) with specific trusted origins. If credentials are needed, ' +
          'you must specify an explicit origin — browsers reject credentials with wildcard origins.',
        fileName: 'Server CORS Configuration',
        originalCode:
          'Access-Control-Allow-Origin: *' +
          (credentialsEnabled ? '\nAccess-Control-Allow-Credentials: true' : ''),
        fixedCode:
          'Access-Control-Allow-Origin: https://yourdomain.com\n' +
          'Vary: Origin',
        remediated: false,
        remediationType: 'config',
      });
    }

    // Check: Credentials with reflected/wildcard origin (standalone finding if not already captured)
    if (credentialsEnabled && acao && acao.trim() !== '*' && acao.trim() !== evilOrigin) {
      // Credentials are enabled but origin wasn't reflected — still worth noting if
      // the ACAO is overly permissive (e.g. a broad subdomain or known-weak value)
      // For now, we only flag if acao is present but not restricted enough.
    }
  }

  // --- Probe 2: Null Origin ---
  const nullProbe = await sendCORSProbe(targetUrl, 'null');

  if (nullProbe) {
    const acao = nullProbe.headers.get('access-control-allow-origin');
    const acac = nullProbe.headers.get('access-control-allow-credentials');
    const credentialsEnabled = acac && acac.trim().toLowerCase() === 'true';

    if (acao && acao.trim().toLowerCase() === 'null') {
      findings.push({
        title: 'CORS Null Origin Accepted',
        severity: credentialsEnabled ? 'high' : 'medium',
        category: 'DAST Audit',
        description:
          'The server accepts "null" as a valid Origin and reflects it in Access-Control-Allow-Origin. ' +
          'The null origin is sent by sandboxed iframes, local file:// pages, and certain redirect chains. ' +
          'An attacker can exploit this using a sandboxed iframe to bypass CORS restrictions.' +
          (credentialsEnabled
            ? ' Combined with Access-Control-Allow-Credentials: true, authenticated data can be stolen.'
            : ''),
        impact:
          'An attacker can use a sandboxed iframe (e.g., <iframe sandbox="allow-scripts">) to send requests ' +
          'with a null Origin and read cross-origin responses, potentially accessing sensitive data or performing actions ' +
          'on behalf of authenticated users.',
        solution:
          'Do not include "null" in your list of allowed origins. The null origin should never be trusted as it can be ' +
          'easily forged via sandboxed iframes. Remove "null" from any origin allowlists.',
        fileName: 'Server CORS Configuration',
        originalCode:
          'Access-Control-Allow-Origin: null' +
          (credentialsEnabled ? '\nAccess-Control-Allow-Credentials: true' : ''),
        fixedCode:
          '// Do not allow null origin\n' +
          'if (origin === "null" || !ALLOWED_ORIGINS.includes(origin)) {\n' +
          '  // Do not set Access-Control-Allow-Origin header\n' +
          '  return;\n' +
          '}',
        remediated: false,
        remediationType: 'config',
      });
    }
  }

  const endTime = Date.now();
  const metadata = {
    scanner: 'CORS Misconfiguration Scanner',
    targetUrl,
    totalFindings: findings.length,
    probesExecuted: 2,
    scanDurationMs: endTime - startTime,
    timestamp: new Date().toISOString(),
  };

  return { findings, metadata };
}

module.exports = { scanCORS };
