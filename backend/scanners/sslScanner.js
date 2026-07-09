/**
 * Geolzen SSL/TLS Certificate & Protocol Scanner
 * 
 * Uses Node.js built-in `tls` module to connect to a target host
 * and inspect the SSL certificate details and protocol version.
 * This is the same handshake any HTTPS client performs.
 */

const tls = require('tls');

/**
 * Scan a target domain for SSL/TLS certificate and protocol issues
 * @param {string} hostname - The domain to check (e.g., example.com)
 * @returns {Promise<object>} - Scan results with findings and metadata
 */
async function scanSSL(hostname) {
  const findings = [];
  const metadata = {
    scanner: 'geolzen-ssl-scanner',
    hostname,
    startTime: new Date().toISOString(),
    certificate: null,
    protocol: null
  };

  try {
    const certInfo = await getCertificateInfo(hostname);
    metadata.certificate = certInfo;
    metadata.protocol = certInfo.protocol;

    // Check certificate expiration
    const now = new Date();
    const expiresAt = new Date(certInfo.validTo);
    const daysUntilExpiry = Math.ceil((expiresAt - now) / (1000 * 60 * 60 * 24));

    if (daysUntilExpiry <= 0) {
      findings.push({
        title: 'SSL/TLS Certificate Has Expired',
        severity: 'critical',
        category: 'Network Recon',
        description: `The SSL certificate for ${hostname} expired on ${certInfo.validTo}. Browsers will display security warnings to users, and encrypted connections may be rejected by strict clients.`,
        impact: 'Critical. Expired certificates break HTTPS trust chains. Users see browser warnings, automated clients reject connections, and attackers can more easily perform man-in-the-middle attacks.',
        solution: 'Renew the SSL certificate immediately through your certificate authority (e.g., Let\'s Encrypt, DigiCert, or your cloud provider\'s certificate manager).',
        fileName: `SSL Certificate: ${hostname}:443`,
        originalCode: `Certificate Status: EXPIRED\nExpired: ${certInfo.validTo}\nIssuer: ${certInfo.issuer}`,
        fixedCode: `Certificate Status: VALID\nExpires: [Future Date]\nIssuer: ${certInfo.issuer}`,
        remediated: false,
        remediationType: 'config'
      });
    } else if (daysUntilExpiry <= 30) {
      findings.push({
        title: `SSL/TLS Certificate Expires in ${daysUntilExpiry} Days`,
        severity: 'medium',
        category: 'Network Recon',
        description: `The SSL certificate for ${hostname} will expire on ${certInfo.validTo} (${daysUntilExpiry} days remaining). If the certificate is not renewed before expiration, HTTPS connections will fail.`,
        impact: 'Medium. Certificate expiration causes service disruption and trust warnings for all visitors.',
        solution: 'Schedule certificate renewal before the expiration date. Consider enabling auto-renewal with Let\'s Encrypt or your cloud provider\'s certificate management service.',
        fileName: `SSL Certificate: ${hostname}:443`,
        originalCode: `Certificate Expires: ${certInfo.validTo}\nDays Remaining: ${daysUntilExpiry}`,
        fixedCode: `Certificate Expires: [Renewed Date]\nAuto-Renewal: Enabled`,
        remediated: false,
        remediationType: 'config'
      });
    }

    // Check if certificate is self-signed
    if (certInfo.subject === certInfo.issuer) {
      findings.push({
        title: 'Self-Signed SSL Certificate Detected',
        severity: 'high',
        category: 'Network Recon',
        description: `The SSL certificate for ${hostname} is self-signed (issuer matches subject: "${certInfo.issuer}"). Self-signed certificates are not trusted by browsers or operating systems and provide no identity verification.`,
        impact: 'High. Browsers display security warnings, users cannot trust the server identity, and the connection is vulnerable to man-in-the-middle attacks.',
        solution: 'Replace the self-signed certificate with one issued by a trusted Certificate Authority. Free options include Let\'s Encrypt (certbot) or Cloudflare Origin certificates.',
        fileName: `SSL Certificate: ${hostname}:443`,
        originalCode: `Subject: ${certInfo.subject}\nIssuer: ${certInfo.issuer}\nType: Self-Signed`,
        fixedCode: `Subject: ${certInfo.subject}\nIssuer: Let's Encrypt Authority X3\nType: CA-Signed`,
        remediated: false,
        remediationType: 'config'
      });
    }

    // Check Subject Alternative Names (SAN) coverage
    if (certInfo.subjectAltNames && certInfo.subjectAltNames.length > 0) {
      const coversWildcard = certInfo.subjectAltNames.some(san => san.startsWith('*.'));
      const coversDomain = certInfo.subjectAltNames.some(san =>
        san === hostname || san === `*.${hostname.split('.').slice(1).join('.')}`
      );

      if (!coversDomain) {
        findings.push({
          title: 'SSL Certificate Does Not Cover Target Domain',
          severity: 'high',
          category: 'Network Recon',
          description: `The SSL certificate does not include "${hostname}" in its Subject Alternative Names. SANs listed: ${certInfo.subjectAltNames.join(', ')}. This causes certificate mismatch warnings in browsers.`,
          impact: 'High. Certificate mismatch breaks HTTPS trust and displays prominent browser security warnings.',
          solution: `Reissue the certificate to include "${hostname}" as a Subject Alternative Name.`,
          fileName: `SSL Certificate: ${hostname}:443`,
          originalCode: `SANs: ${certInfo.subjectAltNames.join(', ')}`,
          fixedCode: `SANs: ${hostname}, ${certInfo.subjectAltNames.join(', ')}`,
          remediated: false,
          remediationType: 'config'
        });
      }
    }

    // Check TLS protocol version
    if (certInfo.protocol) {
      const version = certInfo.protocol;
      if (version === 'TLSv1' || version === 'TLSv1.1') {
        findings.push({
          title: `Deprecated ${version} Protocol in Use`,
          severity: 'high',
          category: 'Network Recon',
          description: `The server negotiated a connection using ${version}, which is officially deprecated by IETF RFC 8996. These older protocols contain known cryptographic weaknesses including BEAST, POODLE, and CRIME attacks.`,
          impact: 'High. Attackers capable of intercepting traffic can perform cryptographic downgrade attacks to decrypt secure communications.',
          solution: 'Configure the server to only support TLS 1.2 and TLS 1.3. Disable TLSv1 and TLSv1.1 in your web server configuration.',
          fileName: `TLS Configuration: ${hostname}:443`,
          originalCode: `ssl_protocols TLSv1 TLSv1.1 TLSv1.2;\nssl_ciphers HIGH:!aNULL:!MD5;`,
          fixedCode: `ssl_protocols TLSv1.2 TLSv1.3;\nssl_prefer_server_ciphers on;\nssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;`,
          remediated: false,
          remediationType: 'config'
        });
      }
    }

  } catch (err) {
    if (err.code === 'ECONNREFUSED') {
      metadata.error = `Port 443 is not accepting connections on ${hostname}`;
    } else if (err.code === 'ENOTFOUND') {
      metadata.error = `DNS resolution failed for ${hostname}`;
    } else if (err.code === 'ETIMEDOUT') {
      metadata.error = `Connection timed out connecting to ${hostname}:443`;
    } else {
      metadata.error = err.message;
    }
  }

  metadata.endTime = new Date().toISOString();
  metadata.findingsCount = findings.length;

  return { findings, metadata };
}

/**
 * Connect to a host via TLS and extract certificate details
 */
function getCertificateInfo(hostname) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(443, hostname, {
      servername: hostname,
      rejectUnauthorized: false, // We want to inspect even invalid certs
      timeout: 10000
    }, () => {
      const cert = socket.getPeerCertificate(true);
      const protocol = socket.getProtocol();

      const info = {
        subject: cert.subject ? (cert.subject.CN || JSON.stringify(cert.subject)) : 'Unknown',
        issuer: cert.issuer ? (cert.issuer.O || cert.issuer.CN || JSON.stringify(cert.issuer)) : 'Unknown',
        validFrom: cert.valid_from,
        validTo: cert.valid_to,
        serialNumber: cert.serialNumber,
        fingerprint: cert.fingerprint256 || cert.fingerprint,
        protocol: protocol,
        subjectAltNames: [],
        authorized: socket.authorized
      };

      // Parse Subject Alternative Names
      if (cert.subjectaltname) {
        info.subjectAltNames = cert.subjectaltname
          .split(', ')
          .map(san => san.replace('DNS:', '').trim());
      }

      socket.end();
      resolve(info);
    });

    socket.on('error', (err) => {
      socket.destroy();
      reject(err);
    });

    socket.setTimeout(10000, () => {
      socket.destroy();
      reject(new Error('Connection timed out'));
    });
  });
}

module.exports = { scanSSL };
