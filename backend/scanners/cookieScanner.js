/**
 * Cookie Security Scanner
 * Analyzes Set-Cookie response headers for security misconfigurations
 * including missing Secure, HttpOnly, SameSite flags, and overly broad
 * domain scoping.
 */

const USER_AGENT = 'Geolzen-Security-Scanner/1.0 (Authorized Vulnerability Assessment)';
const TIMEOUT_MS = 8000;

/**
 * Parses a single Set-Cookie header string into a structured object.
 * @param {string} setCookieStr - Raw Set-Cookie header value
 * @returns {Object} Parsed cookie with name, value, and attributes
 */
function parseCookie(setCookieStr) {
  const parts = setCookieStr.split(';').map((p) => p.trim());
  const [nameValue, ...attributes] = parts;

  const eqIndex = nameValue.indexOf('=');
  const name = eqIndex !== -1 ? nameValue.substring(0, eqIndex).trim() : nameValue.trim();
  const value = eqIndex !== -1 ? nameValue.substring(eqIndex + 1).trim() : '';

  const cookie = {
    name,
    value,
    secure: false,
    httpOnly: false,
    sameSite: null,
    domain: null,
    path: null,
    expires: null,
    maxAge: null,
    raw: setCookieStr,
  };

  for (const attr of attributes) {
    const lowerAttr = attr.toLowerCase();

    if (lowerAttr === 'secure') {
      cookie.secure = true;
    } else if (lowerAttr === 'httponly') {
      cookie.httpOnly = true;
    } else if (lowerAttr.startsWith('samesite=')) {
      cookie.sameSite = attr.split('=')[1]?.trim() || null;
    } else if (lowerAttr.startsWith('domain=')) {
      cookie.domain = attr.split('=')[1]?.trim() || null;
    } else if (lowerAttr.startsWith('path=')) {
      cookie.path = attr.split('=')[1]?.trim() || null;
    } else if (lowerAttr.startsWith('expires=')) {
      cookie.expires = attr.substring(attr.indexOf('=') + 1).trim();
    } else if (lowerAttr.startsWith('max-age=')) {
      cookie.maxAge = attr.split('=')[1]?.trim() || null;
    }
  }

  return cookie;
}

/**
 * Extracts all Set-Cookie headers from a fetch Response.
 * Uses the raw headers approach since fetch coalesces Set-Cookie by default.
 * @param {Response} response - The fetch Response object
 * @returns {string[]} Array of Set-Cookie header values
 */
function extractSetCookieHeaders(response) {
  // Node.js fetch (undici) supports response.headers.getSetCookie()
  if (typeof response.headers.getSetCookie === 'function') {
    return response.headers.getSetCookie();
  }

  // Fallback: try to get the combined header and split heuristically
  const combined = response.headers.get('set-cookie');
  if (!combined) return [];

  // Split on comma followed by a cookie name pattern (name=)
  // This is a heuristic since cookie values can contain commas (e.g. in Expires dates)
  const cookies = [];
  let current = '';
  const segments = combined.split(',');

  for (let i = 0; i < segments.length; i++) {
    const segment = segments[i].trim();

    // Check if this segment starts a new cookie (contains name=value before any ;)
    const beforeSemicolon = segment.split(';')[0];
    if (current && beforeSemicolon.includes('=') && !beforeSemicolon.match(/^\s*(Mon|Tue|Wed|Thu|Fri|Sat|Sun)/i)) {
      cookies.push(current.trim());
      current = segment;
    } else {
      current = current ? current + ', ' + segment : segment;
    }
  }

  if (current) {
    cookies.push(current.trim());
  }

  return cookies;
}

/**
 * Checks if a domain value is overly broad (e.g., a TLD or public suffix).
 * @param {string} domain - The domain value from the cookie
 * @param {string} targetHost - The hostname of the target URL
 * @returns {boolean}
 */
function isOverlyBroadDomain(domain, targetHost) {
  if (!domain) return false;

  const cleanDomain = domain.startsWith('.') ? domain.substring(1) : domain;

  // Check if the domain is a parent of the target host (broader scope)
  if (targetHost !== cleanDomain && targetHost.endsWith('.' + cleanDomain)) {
    // The cookie domain is broader than the target host
    const domainParts = cleanDomain.split('.');

    // Very broad if it's just a TLD or second-level domain (e.g., .com, .co.uk, .example.com)
    if (domainParts.length <= 2) {
      return true;
    }

    // Check if the domain is a higher-level parent when more specific scoping is possible
    const targetParts = targetHost.split('.');
    if (targetParts.length > domainParts.length + 1) {
      return true;
    }
  }

  // Leading dot means it applies to all subdomains
  if (domain.startsWith('.')) {
    return true;
  }

  return false;
}

/**
 * Scans a target URL for cookie security misconfigurations.
 * @param {string} targetUrl - The URL to scan
 * @returns {Promise<{findings: Array, metadata: Object}>}
 */
async function scanCookies(targetUrl) {
  const findings = [];
  const startTime = Date.now();

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), TIMEOUT_MS);

  let response;
  try {
    response = await fetch(targetUrl, {
      method: 'GET',
      headers: {
        'User-Agent': USER_AGENT,
      },
      signal: controller.signal,
      redirect: 'follow',
    });
    clearTimeout(timeoutId);
  } catch (error) {
    clearTimeout(timeoutId);
    const endTime = Date.now();

    if (error.name === 'AbortError') {
      console.error(`[Cookie Scanner] Request to ${targetUrl} timed out after ${TIMEOUT_MS}ms`);
    } else {
      console.error(`[Cookie Scanner] Request failed for ${targetUrl}: ${error.message}`);
    }

    return {
      findings: [],
      metadata: {
        scanner: 'Cookie Security Scanner',
        targetUrl,
        totalFindings: 0,
        cookiesAnalyzed: 0,
        scanDurationMs: endTime - startTime,
        error: error.name === 'AbortError' ? 'Request timed out' : error.message,
        timestamp: new Date().toISOString(),
      },
    };
  }

  // Extract and parse cookies
  const setCookieHeaders = extractSetCookieHeaders(response);
  const cookies = setCookieHeaders.map(parseCookie);

  let targetHost;
  try {
    targetHost = new URL(targetUrl).hostname;
  } catch {
    targetHost = '';
  }

  const isHTTPS = targetUrl.toLowerCase().startsWith('https://');

  // Analyze each cookie
  for (const cookie of cookies) {
    const cookieName = cookie.name || '(unnamed)';

    // Check: Missing Secure flag
    if (!cookie.secure) {
      findings.push({
        title: `Cookie "${cookieName}" Missing Secure Flag`,
        severity: 'medium',
        category: 'DAST Audit',
        description:
          `The cookie "${cookieName}" is set without the Secure flag. ` +
          'Without this flag, the cookie will be sent over unencrypted HTTP connections, ' +
          'making it vulnerable to interception via man-in-the-middle (MITM) attacks. ' +
          (isHTTPS
            ? 'Although the site uses HTTPS, the cookie could still be sent if the user navigates to an HTTP version of the site.'
            : 'The site appears to use HTTP, making this especially critical.'),
        impact:
          'Sensitive cookie data (session tokens, authentication credentials) can be intercepted by attackers ' +
          'on the same network through packet sniffing or MITM attacks, potentially leading to session hijacking.',
        solution:
          'Add the Secure flag to the Set-Cookie header to ensure the cookie is only transmitted over HTTPS connections.',
        fileName: 'Server Cookie Configuration',
        originalCode: `Set-Cookie: ${cookie.raw}`,
        fixedCode: `Set-Cookie: ${cookie.raw}; Secure`,
        remediated: false,
        remediationType: 'config',
      });
    }

    // Check: Missing HttpOnly flag
    if (!cookie.httpOnly) {
      findings.push({
        title: `Cookie "${cookieName}" Missing HttpOnly Flag`,
        severity: 'medium',
        category: 'DAST Audit',
        description:
          `The cookie "${cookieName}" is set without the HttpOnly flag. ` +
          'This allows client-side JavaScript to access the cookie via document.cookie, ' +
          'making it vulnerable to exfiltration through Cross-Site Scripting (XSS) attacks.',
        impact:
          'If the application has an XSS vulnerability, an attacker can steal this cookie using JavaScript ' +
          '(e.g., document.cookie), potentially hijacking user sessions or extracting sensitive data.',
        solution:
          'Add the HttpOnly flag to the Set-Cookie header to prevent JavaScript access to the cookie. ' +
          'This does not prevent the cookie from being sent with requests, it only blocks client-side script access.',
        fileName: 'Server Cookie Configuration',
        originalCode: `Set-Cookie: ${cookie.raw}`,
        fixedCode: `Set-Cookie: ${cookie.raw}; HttpOnly`,
        remediated: false,
        remediationType: 'config',
      });
    }

    // Check: Missing or weak SameSite attribute
    const sameSiteValue = cookie.sameSite ? cookie.sameSite.toLowerCase() : null;
    if (!sameSiteValue || sameSiteValue === 'none') {
      const isMissing = !cookie.sameSite;
      findings.push({
        title: `Cookie "${cookieName}" ${isMissing ? 'Missing' : 'Weak'} SameSite Attribute`,
        severity: 'low',
        category: 'DAST Audit',
        description:
          `The cookie "${cookieName}" ${isMissing ? 'does not have a SameSite attribute set' : 'has SameSite set to "None"'}. ` +
          (isMissing
            ? 'Without SameSite, most modern browsers default to "Lax", but older browsers may default to "None", ' +
              'allowing the cookie to be sent with all cross-site requests.'
            : 'SameSite=None explicitly allows the cookie to be sent with all cross-site requests. ') +
          'This increases exposure to Cross-Site Request Forgery (CSRF) attacks.',
        impact:
          'Cross-site requests from attacker-controlled pages will include this cookie, potentially enabling CSRF attacks ' +
          'where an attacker can perform unauthorized actions on behalf of the authenticated user.',
        solution:
          `Set the SameSite attribute to "Strict" or "Lax" depending on your application's cross-origin requirements. ` +
          'Use "Strict" for maximum protection, or "Lax" if the cookie needs to be sent with top-level navigations.',
        fileName: 'Server Cookie Configuration',
        originalCode: `Set-Cookie: ${cookie.raw}`,
        fixedCode: `Set-Cookie: ${cookie.name}=${cookie.value}; SameSite=Lax; Secure; HttpOnly; Path=${cookie.path || '/'}`,
        remediated: false,
        remediationType: 'config',
      });
    }

    // Check: Overly broad Domain scoping
    if (cookie.domain && isOverlyBroadDomain(cookie.domain, targetHost)) {
      findings.push({
        title: `Cookie "${cookieName}" Has Overly Broad Domain Scope`,
        severity: 'low',
        category: 'DAST Audit',
        description:
          `The cookie "${cookieName}" is scoped to the domain "${cookie.domain}", which is broader than necessary. ` +
          'A leading dot or parent domain scope means the cookie will be sent to all subdomains, ' +
          'increasing the attack surface if any subdomain is compromised or less secure.',
        impact:
          'If any subdomain under "' + cookie.domain + '" is compromised (e.g., via subdomain takeover or an insecure staging site), ' +
          'attackers on that subdomain can access this cookie. This is particularly dangerous for session cookies ' +
          'as it enables session hijacking from less-secure subdomains.',
        solution:
          'Restrict the cookie domain to the most specific scope required. ' +
          `Omit the Domain attribute entirely to limit the cookie to the exact host "${targetHost}", ` +
          'or set it to the most specific subdomain needed.',
        fileName: 'Server Cookie Configuration',
        originalCode: `Set-Cookie: ${cookie.raw}`,
        fixedCode: `Set-Cookie: ${cookie.name}=${cookie.value}; Path=${cookie.path || '/'}; Secure; HttpOnly; SameSite=Lax`,
        remediated: false,
        remediationType: 'config',
      });
    }
  }

  const endTime = Date.now();
  const metadata = {
    scanner: 'Cookie Security Scanner',
    targetUrl,
    totalFindings: findings.length,
    cookiesAnalyzed: cookies.length,
    cookieNames: cookies.map((c) => c.name),
    scanDurationMs: endTime - startTime,
    timestamp: new Date().toISOString(),
  };

  return { findings, metadata };
}

module.exports = { scanCookies };
