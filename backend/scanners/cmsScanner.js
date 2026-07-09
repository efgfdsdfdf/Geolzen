/**
 * Geolzen CMS & App Layer Scanner
 * 
 * Performs active HTTP GET requests to target applications to scrape
 * HTML bodies, looking for exposed paths, vulnerable generator tags,
 * and inline information disclosures.
 */

async function checkRoute(baseUrl, path) {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);
    
    const response = await fetch(`${baseUrl}${path}`, {
      method: 'GET',
      redirect: 'manual', // don't follow login redirects for admin panel checks
      signal: controller.signal,
      headers: { 'User-Agent': 'Geolzen-Security-Scanner/1.0' }
    });
    
    clearTimeout(timeout);
    
    // If it returns 200 OK, it means the panel is exposed
    return { path, status: response.status, exposed: response.status === 200 };
  } catch (err) {
    return { path, status: 0, exposed: false, error: err.message };
  }
}

async function scanCMS(targetUrl) {
  const findings = [];
  const metadata = {
    targetUrl,
    startTime: new Date().toISOString(),
    error: null
  };

  try {
    // 1. Check for exposed admin panels
    const commonAdminPaths = ['/wp-admin/', '/admin/', '/administrator/', '/login.php'];
    const adminChecks = await Promise.all(commonAdminPaths.map(p => checkRoute(targetUrl, p)));
    
    for (const check of adminChecks) {
      if (check.exposed) {
        findings.push({
          title: `Exposed Admin Panel Route (${check.path})`,
          severity: 'medium',
          category: 'DAST Audit',
          description: `The administrative interface at ${check.path} is publicly accessible. Exposed admin panels are prime targets for brute-force attacks and vulnerability exploitation.`,
          impact: 'Medium. Attackers can attempt to guess administrator passwords or exploit zero-day vulnerabilities in the CMS software.',
          solution: 'Restrict access to administrative interfaces using IP whitelisting or place them behind a VPN/Zero-Trust gateway.',
          fileName: `Web Server Routing: ${check.path}`,
          originalCode: `# Current Access\nRoute: ${check.path}\nStatus: Publicly Accessible (HTTP 200)`,
          fixedCode: `# Recommended Access Control (Nginx)\nlocation ${check.path} {\n  allow <Trusted_IP>;\n  deny all;\n}`,
          remediated: false,
          remediationType: 'config'
        });
      }
    }

    // 2. Fetch the homepage HTML to check for generator tags and inline disclosures
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);
    
    const response = await fetch(targetUrl, {
      method: 'GET',
      signal: controller.signal,
      headers: { 'User-Agent': 'Geolzen-Security-Scanner/1.0' }
    });
    
    clearTimeout(timeout);
    
    if (response.ok) {
      const html = await response.text();
      
      // Check for WordPress/Drupal/Joomla generator tags
      const generatorMatch = html.match(/<meta name=["']generator["'] content=["']([^"']+)["']/i);
      if (generatorMatch && generatorMatch[1]) {
        const generator = generatorMatch[1];
        
        // Let's flag any exposed generator tag as info disclosure
        findings.push({
          title: 'CMS Version Disclosure',
          severity: 'low',
          category: 'DAST Audit',
          description: `The application exposes its CMS and version via the meta generator tag: "${generator}". Version disclosure makes it trivial for attackers to look up known exploits.`,
          impact: 'Low. Helps attackers tailor their exploits to the exact software version running.',
          solution: 'Remove the meta generator tag from the HTML head. Many CMS platforms have plugins or core settings to disable version disclosure.',
          fileName: `HTML Response: ${targetUrl}`,
          originalCode: `<meta name="generator" content="${generator}">`,
          fixedCode: `<!-- Remove this meta tag entirely -->`,
          remediated: false,
          remediationType: 'code'
        });
      }
      
      // Check for hardcoded API keys or tokens (very naive regex for demonstration)
      const apiKeyMatch = html.match(/['"](sk_live_[a-zA-Z0-9]+)['"]/);
      if (apiKeyMatch) {
        findings.push({
          title: 'Exposed Secret Key in Client-Side Code',
          severity: 'critical',
          category: 'DAST Audit',
          description: `A live secret key (${apiKeyMatch[1].substring(0, 10)}...) was found embedded directly in the HTML source code.`,
          impact: 'Critical. Attackers can extract this key and use it to perform authenticated actions against third-party APIs on your behalf.',
          solution: 'Immediately revoke the exposed secret key in the third-party dashboard. Move the usage of this key to a secure backend server.',
          fileName: `HTML Response: ${targetUrl}`,
          originalCode: `const api_key = "${apiKeyMatch[1]}";`,
          fixedCode: `// Fetch data from secure backend endpoint instead\nconst data = await fetch('/api/secure-route');`,
          remediated: false,
          remediationType: 'code'
        });
      }
    }
  } catch (err) {
    metadata.error = err.message;
  }

  metadata.endTime = new Date().toISOString();
  return { findings, metadata };
}

module.exports = { scanCMS };
