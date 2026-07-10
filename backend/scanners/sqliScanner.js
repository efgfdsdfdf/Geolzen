/**
 * Error-Based SQL Injection Scanner
 *
 * Tests for SQL injection vulnerabilities by appending safe detection
 * payloads to common query parameters and checking the response body
 * for known database error signatures.
 *
 * Category: DAST Audit
 */

const PAYLOADS = [
  "'",
  "' OR '1'='1",
  "1' AND '1'='1",
  '1 UNION SELECT NULL--',
  "' OR 1=1--",
];

const PARAMETER_NAMES = [
  'id', 'user', 'page', 'category',
  'item', 'product', 'article', 'order',
];

const ERROR_SIGNATURES = [
  /SQL syntax/i,
  /mysql_fetch/i,
  /ORA-/,
  /PostgreSQL.*ERROR/i,
  /sqlite3/i,
  /SQLSTATE/i,
  /Unclosed quotation/i,
  /syntax error at or near/i,
  /Microsoft OLE DB/i,
  /ODBC SQL Server Driver/i,
  /mysql_num_rows/i,
  /pg_query/i,
  /Warning.*mysql_/i,
];

const REQUEST_TIMEOUT_MS = 5000;

/**
 * Build a test URL by setting the given parameter to the payload value.
 */
function buildTestUrl(targetUrl, param, payload) {
  const url = new URL(targetUrl);
  url.searchParams.set(param, payload);
  return url.toString();
}

/**
 * Send a probe request and return the response body text.
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
 * Check a response body for any known SQL error signature.
 * Returns the first matched signature string, or null.
 */
function matchErrorSignature(body) {
  for (const pattern of ERROR_SIGNATURES) {
    const match = body.match(pattern);
    if (match) return match[0];
  }
  return null;
}

/**
 * Create a finding object for a confirmed SQL injection.
 */
function createFinding(targetUrl, param, payload, errorSignature) {
  return {
    title: `SQL Injection via parameter "${param}"`,
    severity: 'critical',
    category: 'DAST Audit',
    description:
      `The parameter "${param}" is vulnerable to SQL injection at ${targetUrl}. ` +
      `Sending the payload ${payload} caused the server to return a database error containing "${errorSignature}". ` +
      'This indicates that user input is being concatenated directly into SQL queries without sanitization.',
    impact:
      'An attacker can read, modify, or delete arbitrary data in the database, ' +
      'bypass authentication, escalate privileges, or execute operating system commands ' +
      'on the underlying server in some configurations.',
    solution:
      'Use parameterized queries (prepared statements) for all database interactions. ' +
      'Never concatenate user input into SQL strings. Implement an ORM or query builder ' +
      'that automatically handles escaping. Apply least-privilege database accounts.',
    fileName: new URL(targetUrl).pathname || '/',
    originalCode:
      `// Vulnerable: user input concatenated into SQL\n` +
      `const query = "SELECT * FROM items WHERE ${param} = '" + req.query.${param} + "'";\n` +
      `db.query(query);`,
    fixedCode:
      `// Fixed: use parameterized query\n` +
      `const query = "SELECT * FROM items WHERE ${param} = ?";\n` +
      `db.query(query, [req.query.${param}]);`,
    remediated: false,
    remediationType: 'code',
  };
}

/**
 * Scan a target URL for error-based SQL injection vulnerabilities.
 *
 * @param {string} targetUrl - The base URL to test.
 * @returns {{ findings: Array, metadata: Object }}
 */
async function scanSQLi(targetUrl) {
  const findings = [];
  const testedCombinations = [];
  const vulnerableParams = new Set();
  const startTime = Date.now();
  let requestCount = 0;

  for (const param of PARAMETER_NAMES) {
    if (vulnerableParams.has(param)) continue;

    for (const payload of PAYLOADS) {
      if (vulnerableParams.has(param)) break;

      const testUrl = buildTestUrl(targetUrl, param, payload);
      testedCombinations.push({ param, payload });
      requestCount++;

      const body = await sendProbe(testUrl);

      if (body) {
        const errorSignature = matchErrorSignature(body);
        if (errorSignature) {
          findings.push(createFinding(targetUrl, param, payload, errorSignature));
          vulnerableParams.add(param);
        }
      }
    }
  }

  const elapsedMs = Date.now() - startTime;

  return {
    findings,
    metadata: {
      scanner: 'sqliScanner',
      target: targetUrl,
      totalRequests: requestCount,
      totalFindings: findings.length,
      parametersChecked: PARAMETER_NAMES.length,
      payloadsUsed: PAYLOADS.length,
      errorSignaturesChecked: ERROR_SIGNATURES.length,
      elapsedMs,
      testedCombinations,
    },
  };
}

module.exports = { scanSQLi };
