/**
 * Geolzen Active Port Scanner
 * 
 * Performs active TCP connections to common management and database ports
 * to identify exposed infrastructure.
 */
const net = require('net');

const TARGET_PORTS = [
  { port: 21, service: 'FTP', severity: 'high', description: 'File Transfer Protocol is unencrypted and should not be exposed to the internet. Credentials and data are sent in plaintext.', solution: 'Disable FTP and use SFTP (SSH File Transfer Protocol) instead. Configure your firewall to block port 21.' },
  { port: 22, service: 'SSH', severity: 'medium', description: 'Secure Shell is exposed to the internet. While encrypted, exposing SSH allows attackers to perform brute-force password guessing attacks.', solution: 'Restrict SSH access (port 22) to specific trusted IP addresses or a VPN using a firewall or security group.' },
  { port: 23, service: 'Telnet', severity: 'critical', description: 'Telnet is a legacy protocol that sends all data, including passwords, in plaintext.', solution: 'Immediately disable the Telnet service. Use SSH for remote management and block port 23.' },
  { port: 3306, service: 'MySQL', severity: 'critical', description: 'A MySQL database is exposed directly to the internet. This provides attackers a direct vector to exploit database vulnerabilities or brute-force credentials.', solution: 'Block external access to port 3306. Databases should only be accessible from trusted internal application servers.' },
  { port: 3389, service: 'RDP', severity: 'critical', description: 'Remote Desktop Protocol is exposed. RDP is frequently targeted by ransomware operators and is vulnerable to brute-force attacks and known exploits (e.g. BlueKeep).', solution: 'Disable RDP access from the internet. Require users to connect to a VPN or use a secure remote gateway before accessing RDP.' },
  { port: 5432, service: 'PostgreSQL', severity: 'critical', description: 'A PostgreSQL database is exposed directly to the internet, risking data exfiltration or credential brute-forcing.', solution: 'Block external access to port 5432. Configure pg_hba.conf to only allow connections from known internal IPs.' }
];

function checkPort(host, portInfo) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let isOpen = false;

    socket.setTimeout(2000); // Fast timeout for scanning

    socket.on('connect', () => {
      isOpen = true;
      socket.destroy();
    });

    socket.on('timeout', () => {
      socket.destroy();
    });

    socket.on('error', () => {
      // Ignored, port is closed or filtered
    });

    socket.on('close', () => {
      resolve({ ...portInfo, isOpen });
    });

    socket.connect(portInfo.port, host);
  });
}

/**
 * Scan common ports on a target host
 * @param {string} hostname - Domain name or IP address
 * @returns {Promise<object>} Findings and metadata
 */
async function scanPorts(hostname) {
  const findings = [];
  const metadata = {
    target: hostname,
    startTime: new Date().toISOString(),
    portsScanned: TARGET_PORTS.length,
    openPorts: 0,
    error: null
  };

  try {
    // Scan all ports concurrently
    const promises = TARGET_PORTS.map(portInfo => checkPort(hostname, portInfo));
    const results = await Promise.all(promises);

    for (const result of results) {
      if (result.isOpen) {
        metadata.openPorts++;
        findings.push({
          title: `Exposed ${result.service} Service (Port ${result.port})`,
          severity: result.severity,
          category: 'Network Recon',
          description: result.description,
          impact: `Exposing ${result.service} increases the attack surface, allowing attackers to directly target management or data infrastructure.`,
          solution: result.solution,
          fileName: `Network Firewall: ${hostname}:${result.port}`,
          originalCode: `# Current Firewall Rules\nALLOW IN TCP ${result.port} FROM 0.0.0.0/0`,
          fixedCode: `# Recommended Firewall Rules\nDENY IN TCP ${result.port} FROM 0.0.0.0/0\nALLOW IN TCP ${result.port} FROM <Trusted_IP_Range>`,
          remediated: false,
          remediationType: 'config'
        });
      }
    }
  } catch (err) {
    metadata.error = err.message;
  }

  metadata.endTime = new Date().toISOString();
  return { findings, metadata };
}

module.exports = { scanPorts };
