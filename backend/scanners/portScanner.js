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
  { port: 5432, service: 'PostgreSQL', severity: 'critical', description: 'A PostgreSQL database is exposed directly to the internet, risking data exfiltration or credential brute-forcing.', solution: 'Block external access to port 5432. Configure pg_hba.conf to only allow connections from known internal IPs.' },
  { port: 6379, service: 'Redis', severity: 'critical', description: 'Redis key-value store is exposed to the internet. Redis often runs without authentication by default, allowing attackers to read/write all cached data or write SSH keys for server takeover.', solution: 'Block external access to port 6379. Configure Redis requirepass and bind to 127.0.0.1.' },
  { port: 27017, service: 'MongoDB', severity: 'critical', description: 'MongoDB database is exposed. Older versions bind to all interfaces without authentication, enabling full database access.', solution: 'Block port 27017 externally. Enable authentication and bind to 127.0.0.1.' },
  { port: 9200, service: 'Elasticsearch', severity: 'critical', description: 'Elasticsearch cluster is exposed. No authentication by default allows anyone to query, modify, or delete all indexed data.', solution: 'Block port 9200. Enable X-Pack Security or use a reverse proxy with auth.' },
  { port: 8080, service: 'HTTP-Proxy', severity: 'medium', description: 'HTTP service on port 8080, commonly a dev server or proxy that may lack production security hardening.', solution: 'Ensure this service has the same security controls as the primary web server.' },
  { port: 8443, service: 'HTTPS-Alt', severity: 'low', description: 'HTTPS service on alternative port 8443, may be a management interface or API gateway.', solution: 'Verify this service is intentional and properly secured.' },
  { port: 2375, service: 'Docker-API', severity: 'critical', description: 'Docker daemon API exposed without TLS. Full system compromise vector — attackers can mount host filesystem and execute commands as root.', solution: 'Immediately block port 2375. Never expose the Docker socket to the network.' },
  { port: 11211, service: 'Memcached', severity: 'high', description: 'Memcached exposed to the internet. No authentication mechanism, can be abused for DDoS amplification or data exfiltration.', solution: 'Block port 11211 externally. Bind Memcached to 127.0.0.1.' },
  { port: 6443, service: 'Kubernetes-API', severity: 'critical', description: 'Kubernetes API server exposed. Misconfigured RBAC or anonymous access could allow full cluster takeover.', solution: 'Restrict API access to trusted networks. Disable anonymous auth.' },
  { port: 9090, service: 'Prometheus', severity: 'medium', description: 'Prometheus metrics endpoint exposed, leaking internal application metrics and infrastructure topology.', solution: 'Block port 9090 externally or add authentication.' },
  { port: 5900, service: 'VNC', severity: 'high', description: 'VNC remote desktop exposed. Weak authentication by default with known vulnerabilities.', solution: 'Block port 5900 and use SSH tunneling instead.' },
  { port: 1433, service: 'MSSQL', severity: 'critical', description: 'Microsoft SQL Server exposed directly to the internet.', solution: 'Block port 1433 externally.' }
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
