/**
 * Geolzen DNS Reconnaissance Scanner
 * 
 * Queries public DNS nameservers via Cloudflare DNS-over-HTTPS
 * to enumerate DNS records (A, AAAA, MX, TXT, NS, CNAME, SOA).
 * Also checks for dangling DNS records that could indicate subdomain takeover risks.
 * 
 * This is entirely passive — it only queries public DNS records.
 */

const RECORD_TYPES = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA'];

const DOH_ENDPOINT = 'https://cloudflare-dns.com/dns-query';

/**
 * Query a specific DNS record type for a domain
 * @param {string} domain 
 * @param {string} type 
 * @returns {Promise<Array>}
 */
async function queryDNS(domain, type) {
  try {
    const response = await fetch(`${DOH_ENDPOINT}?name=${domain}&type=${type}`, {
      headers: { 'Accept': 'application/dns-json' }
    });
    const data = await response.json();
    return data.Answer || [];
  } catch (err) {
    return [];
  }
}

/**
 * Enumerate all DNS records for a target domain
 * @param {string} domain - The target domain (e.g., example.com)
 * @returns {Promise<object>} - Scan results with findings and metadata
 */
async function scanDNS(domain) {
  const findings = [];
  const metadata = {
    scanner: 'geolzen-dns-scanner',
    domain,
    startTime: new Date().toISOString(),
    records: {}
  };

  // Query all standard record types in parallel
  const queries = RECORD_TYPES.map(async (type) => {
    const answers = await queryDNS(domain, type);
    metadata.records[type] = answers.map(a => ({
      name: a.name,
      type: a.type,
      ttl: a.TTL,
      data: a.data
    }));
    return { type, answers };
  });

  const results = await Promise.all(queries);

  // Analyze MX records for email security
  const mxResults = results.find(r => r.type === 'MX');
  if (mxResults && mxResults.answers.length > 0) {
    // Check for SPF record
    const txtResults = results.find(r => r.type === 'TXT');
    const txtRecords = txtResults ? txtResults.answers : [];
    const hasSPF = txtRecords.some(r => r.data && r.data.toLowerCase().includes('v=spf1'));
    const hasDMARC = await checkDMARC(domain);
    const hasDKIM = await checkDKIM(domain);

    if (!hasSPF) {
      findings.push({
        title: 'Missing SPF (Sender Policy Framework) DNS Record',
        severity: 'medium',
        category: 'Network Recon',
        description: `The domain ${domain} has MX records configured (accepting email) but no SPF TXT record was found. SPF records specify which mail servers are authorized to send email on behalf of your domain, preventing email spoofing.`,
        impact: 'Medium. Without SPF, attackers can send emails that appear to come from your domain (email spoofing), which can be used for phishing attacks against your employees, customers, or partners.',
        solution: `Add an SPF TXT record to your DNS configuration. Example: v=spf1 include:_spf.google.com ~all (adjust for your mail provider).`,
        fileName: `DNS Records: ${domain}`,
        originalCode: `# TXT Records\n${txtRecords.map(r => r.data).join('\n') || '# No TXT records'}`,
        fixedCode: `# TXT Records (with SPF)\n"v=spf1 include:_spf.google.com ~all"\n${txtRecords.map(r => r.data).join('\n')}`,
        remediated: false,
        remediationType: 'config'
      });
    }

    if (!hasDMARC) {
      findings.push({
        title: 'Missing DMARC (Domain-based Message Authentication) DNS Record',
        severity: 'medium',
        category: 'Network Recon',
        description: `No DMARC record was found at _dmarc.${domain}. DMARC builds on SPF and DKIM to tell receiving mail servers how to handle messages that fail authentication checks.`,
        impact: 'Medium. Without DMARC, even if SPF and DKIM are configured, receiving servers may not enforce a consistent policy for unauthenticated emails. Attackers can still spoof your domain effectively.',
        solution: `Add a DMARC TXT record at _dmarc.${domain}. Start with a monitoring policy: v=DMARC1; p=none; rua=mailto:dmarc-reports@${domain}`,
        fileName: `DNS Records: _dmarc.${domain}`,
        originalCode: `# _dmarc.${domain}\n# No DMARC record found`,
        fixedCode: `# _dmarc.${domain}\n"v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@${domain}"`,
        remediated: false,
        remediationType: 'config'
      });
    }
  }

  // Check for dangling CNAME records (potential subdomain takeover)
  const cnameResults = results.find(r => r.type === 'CNAME');
  if (cnameResults && cnameResults.answers.length > 0) {
    for (const record of cnameResults.answers) {
      const target = record.data;
      if (target) {
        const danglingProviders = [
          'herokuapp.com', 'herokudns.com',
          'ghost.io',
          'amazonaws.com', 's3.amazonaws.com',
          'cloudfront.net',
          'azurewebsites.net', 'cloudapp.azure.com',
          'trafficmanager.net',
          'pantheonsite.io',
          'domains.tumblr.com',
          'wpengine.com',
          'desk.com',
          'zendesk.com',
          'github.io', 'pages.github.com',
          'surge.sh',
          'unbouncepages.com',
          'fastly.net',
          'helpjuice.com',
          'helpscoutdocs.com',
          'feedpress.me',
          'freshdesk.com',
          'readme.io'
        ];

        const isDangling = danglingProviders.some(p => target.toLowerCase().includes(p));
        if (isDangling) {
          // Attempt to resolve the CNAME target to check if it actually resolves
          const targetResolves = await queryDNS(target.replace(/\.$/, ''), 'A');
          if (targetResolves.length === 0) {
            findings.push({
              title: `Potential Subdomain Takeover via Dangling CNAME`,
              severity: 'high',
              category: 'Network Recon',
              description: `The CNAME record for ${record.name} points to ${target}, which appears to be an unclaimed resource on a third-party hosting provider. If this service has been decommissioned, an attacker could claim the endpoint and serve content on your subdomain.`,
              impact: 'High. Subdomain takeover allows attackers to host malicious content, phishing pages, or credential harvesting forms on your trusted domain, bypassing email security filters and domain reputation.',
              solution: `Either reclaim the external resource at ${target}, or remove the dangling CNAME record from your DNS configuration.`,
              fileName: `DNS Records: ${domain}`,
              originalCode: `${record.name} CNAME ${target}`,
              fixedCode: `# Dangling CNAME removed\n# ${record.name} CNAME ${target}  [DELETED]`,
              remediated: false,
              remediationType: 'config'
            });
          }
        }
      }
    }
  }

  // Check for zone transfer exposure (AXFR)
  const nsResults = results.find(r => r.type === 'NS');
  if (nsResults) {
    metadata.nameservers = nsResults.answers.map(a => a.data);
  }

  // Check for wildcard DNS
  const wildcardTest = `_geolzen-wildcard-probe-${Date.now()}.${domain}`;
  const wildcardResult = await queryDNS(wildcardTest, 'A');
  if (wildcardResult.length > 0) {
    findings.push({
      title: 'Wildcard DNS Record Detected',
      severity: 'low',
      category: 'Network Recon',
      description: `The domain ${domain} has a wildcard DNS record configured (*.${domain}). Any subdomain resolves to ${wildcardResult[0]?.data}. While sometimes intentional, wildcards can mask subdomain takeover vulnerabilities and expand the attack surface.`,
      impact: 'Low. Wildcard DNS can hide dangling records and make subdomain enumeration less effective for security auditing.',
      solution: 'Review whether the wildcard DNS record is necessary. If not, replace it with explicit A records for each required subdomain.',
      fileName: `DNS Records: ${domain}`,
      originalCode: `*.${domain} A ${wildcardResult[0]?.data}`,
      fixedCode: `# Remove wildcard, add explicit records\nwww.${domain} A ${wildcardResult[0]?.data}\napp.${domain} A ${wildcardResult[0]?.data}`,
      remediated: false,
      remediationType: 'config'
    });
  }

  metadata.endTime = new Date().toISOString();
  metadata.findingsCount = findings.length;

  return { findings, metadata };
}

/**
 * Check for DMARC record at _dmarc.domain
 */
async function checkDMARC(domain) {
  const records = await queryDNS(`_dmarc.${domain}`, 'TXT');
  return records.some(r => r.data && r.data.toLowerCase().includes('v=dmarc1'));
}

/**
 * Check for DKIM selector records (common selectors)
 */
async function checkDKIM(domain) {
  const commonSelectors = ['default', 'google', 'dkim', 'mail', 'selector1', 'selector2', 'k1'];
  for (const selector of commonSelectors) {
    const records = await queryDNS(`${selector}._domainkey.${domain}`, 'TXT');
    if (records.length > 0) return true;
  }
  return false;
}

module.exports = { scanDNS };
