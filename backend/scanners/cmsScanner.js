/**
 * Geolzen CMS & App Layer Scanner
 * 
 * Performs active HTTP GET requests to target applications to scrape
 * HTML bodies, looking for exposed paths, vulnerable generator tags,
 * inline information disclosures, leaked API keys, and technology fingerprints.
 */

async function checkRoute(baseUrl, path) {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);
    
    const response = await fetch(`${baseUrl}${path}`, {
      method: 'GET',
      redirect: 'manual', // don't follow login redirects for admin panel checks
      signal: controller.signal,
      headers: { 'User-Agent': 'Geolzen-Security-Scanner/1.0 (Authorized Vulnerability Assessment)' }
    });
    
    clearTimeout(timeout);
    
    // If it returns 200 OK, it means the panel is exposed
    return { path, status: response.status, exposed: response.status === 200 };
  } catch (err) {
    return { path, status: 0, exposed: false, error: err.message };
  }
}

// Secret key patterns to search for in HTML source
const SECRET_PATTERNS = [
  { name: 'Stripe Secret Key', regex: /['"]sk_live_[a-zA-Z0-9]{20,}['"]/g, severity: 'critical' },
  { name: 'Stripe Test Secret Key', regex: /['"]sk_test_[a-zA-Z0-9]{20,}['"]/g, severity: 'high' },
  { name: 'AWS Access Key ID', regex: /['"]AKIA[0-9A-Z]{16}['"]/g, severity: 'critical' },
  { name: 'GitHub Personal Access Token', regex: /['"]ghp_[a-zA-Z0-9]{36}['"]/g, severity: 'critical' },
  { name: 'GitHub OAuth Token', regex: /['"]gho_[a-zA-Z0-9]{36}['"]/g, severity: 'critical' },
  { name: 'Google API Key', regex: /['"]AIza[0-9A-Za-z\-_]{35}['"]/g, severity: 'high' },
  { name: 'Slack Bot Token', regex: /['"]xoxb-[0-9]{10,}-[a-zA-Z0-9]{20,}['"]/g, severity: 'critical' },
  { name: 'Slack Webhook URL', regex: /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]+\/B[a-zA-Z0-9_]+\/[a-zA-Z0-9_]+/g, severity: 'high' },
  { name: 'Twilio Account SID', regex: /['"]AC[a-f0-9]{32}['"]/g, severity: 'high' },
  { name: 'SendGrid API Key', regex: /['"]SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}['"]/g, severity: 'critical' },
  { name: 'Mailgun API Key', regex: /['"]key-[a-zA-Z0-9]{32}['"]/g, severity: 'critical' },
  { name: 'Firebase Config', regex: /apiKey\s*[:=]\s*['"][A-Za-z0-9_\-]{30,}['"]/g, severity: 'high' },
  { name: 'Generic Password Assignment', regex: /(?:password|passwd|secret|api_key|apikey|access_token)\s*[:=]\s*['"][^'"]{8,}['"]/gi, severity: 'high' },
  { name: 'Private Key Block', regex: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/g, severity: 'critical' },
  { name: 'JWT Token', regex: /['"]eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}['"]/g, severity: 'high' }
];

// Technology fingerprints to detect in HTML
const TECH_FINGERPRINTS = [
  { name: 'React', test: (html) => html.includes('__REACT_DEVTOOLS_GLOBAL_HOOK__') || html.includes('data-reactroot') || html.includes('_reactRootContainer'), severity: 'low' },
  { name: 'Next.js', test: (html) => html.includes('__NEXT_DATA__') || html.includes('/_next/'), severity: 'low' },
  { name: 'Angular', test: (html) => /ng-version=['"]\d/i.test(html) || html.includes('ng-app') || html.includes('ng-controller'), severity: 'low' },
  { name: 'Vue.js', test: (html) => /data-v-[a-f0-9]{8}/.test(html) || html.includes('__vue__') || html.includes('Vue.js'), severity: 'low' },
  { name: 'jQuery', test: (html) => /jquery[.-](\d+\.\d+\.\d+)/i.test(html), severity: 'low', extractVersion: (html) => { const m = html.match(/jquery[.-](\d+\.\d+\.\d+)/i); return m ? m[1] : null; } },
  { name: 'WordPress', test: (html) => html.includes('/wp-content/') || html.includes('/wp-includes/'), severity: 'low' },
  { name: 'Drupal', test: (html) => html.includes('Drupal.settings') || html.includes('/sites/default/files/'), severity: 'low' },
  { name: 'Joomla', test: (html) => html.includes('/media/jui/') || html.includes('Joomla!'), severity: 'low' },
  { name: 'Bootstrap', test: (html) => /bootstrap[.-](\d+\.\d+)/i.test(html), severity: 'low', extractVersion: (html) => { const m = html.match(/bootstrap[.-](\d+\.\d+(?:\.\d+)?)/i); return m ? m[1] : null; } },
  { name: 'Webpack Dev Server', test: (html) => html.includes('webpackHotUpdate') || html.includes('webpack-dev-server'), severity: 'medium' },
  { name: 'Source Map Reference', test: (html) => /sourceMappingURL=\S+\.map/.test(html), severity: 'medium' }
];

async function scanCMS(targetUrl) {
  const findings = [];
  const metadata = {
    targetUrl,
    startTime: new Date().toISOString(),
    technologies: [],
    adminPanels: [],
    secretsFound: 0,
    error: null
  };

  try {
    // 1. Check for exposed admin panels and management interfaces
    const commonAdminPaths = [
      '/wp-admin/',
      '/wp-login.php',
      '/admin/',
      '/administrator/',
      '/login.php',
      '/phpmyadmin/',
      '/cpanel/',
      '/webmail/',
      '/.well-known/openid-configuration',
      '/api/',
      '/graphql',
      '/swagger-ui/',
      '/api-docs/',
      '/api-docs/swagger.json',
      '/actuator/',
      '/actuator/health',
      '/console/',
      '/manager/html',
      '/_debug/',
      '/debug/',
      '/status',
      '/health'
    ];

    const adminChecks = await Promise.all(commonAdminPaths.map(p => checkRoute(targetUrl, p)));
    
    for (const check of adminChecks) {
      if (check.exposed) {
        metadata.adminPanels.push(check.path);

        // Determine severity based on the type of panel
        let severity = 'medium';
        let description = `The administrative interface at ${check.path} is publicly accessible.`;
        
        if (['/phpmyadmin/', '/cpanel/', '/manager/html', '/console/'].includes(check.path)) {
          severity = 'high';
          description += ' This is a high-privilege management panel that should never be publicly accessible.';
        } else if (['/swagger-ui/', '/api-docs/', '/api-docs/swagger.json', '/graphql'].includes(check.path)) {
          severity = 'medium';
          description += ' Exposed API documentation reveals all available endpoints, request/response schemas, and authentication mechanisms to potential attackers.';
        } else if (['/actuator/', '/actuator/health', '/_debug/', '/debug/'].includes(check.path)) {
          severity = 'high';
          description += ' Debug and actuator endpoints often expose sensitive internal state, environment variables, and stack traces.';
        }

        findings.push({
          title: `Exposed ${check.path.includes('api') || check.path.includes('graphql') || check.path.includes('swagger') ? 'API Documentation' : check.path.includes('debug') || check.path.includes('actuator') ? 'Debug Endpoint' : 'Admin Panel'} (${check.path})`,
          severity,
          category: 'DAST Audit',
          description,
          impact: `${severity === 'high' ? 'High' : 'Medium'}. Attackers can attempt credential brute-forcing, exploit known vulnerabilities, or gather detailed intelligence about the application architecture.`,
          solution: 'Restrict access to administrative and debug interfaces using IP whitelisting, VPN, or Zero-Trust authentication. For API documentation, consider disabling it in production.',
          fileName: `Web Server Routing: ${check.path}`,
          originalCode: `# Current Access\nRoute: ${check.path}\nStatus: Publicly Accessible (HTTP 200)`,
          fixedCode: `# Recommended Access Control (Nginx)\nlocation ${check.path} {\n  allow <Trusted_IP>;\n  deny all;\n}`,
          remediated: false,
          remediationType: 'config'
        });
      }
    }

    // 2. Fetch the homepage HTML for deep analysis
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);
    
    const response = await fetch(targetUrl, {
      method: 'GET',
      signal: controller.signal,
      headers: { 'User-Agent': 'Geolzen-Security-Scanner/1.0 (Authorized Vulnerability Assessment)' }
    });
    
    clearTimeout(timeout);
    
    if (response.ok) {
      const html = await response.text();
      
      // 3. CMS Generator Tag Detection
      const generatorMatch = html.match(/<meta name=["']generator["'] content=["']([^"']+)["']/i);
      if (generatorMatch && generatorMatch[1]) {
        const generator = generatorMatch[1];
        
        findings.push({
          title: `CMS Version Disclosure: ${generator}`,
          severity: 'low',
          category: 'DAST Audit',
          description: `The application exposes its CMS and version via the meta generator tag: "${generator}". Version disclosure makes it trivial for attackers to look up known exploits for this specific release.`,
          impact: 'Low. Helps attackers tailor their exploits to the exact software version running.',
          solution: 'Remove the meta generator tag from the HTML head. Most CMS platforms have plugins or settings to disable version disclosure.',
          fileName: `HTML Response: ${targetUrl}`,
          originalCode: `<meta name="generator" content="${generator}">`,
          fixedCode: `<!-- Generator meta tag removed for security -->`,
          remediated: false,
          remediationType: 'code'
        });
      }

      // 4. Secret Key / Token Detection
      for (const pattern of SECRET_PATTERNS) {
        const matches = html.match(pattern.regex);
        if (matches && matches.length > 0) {
          metadata.secretsFound += matches.length;
          const sanitizedMatch = matches[0].substring(0, 20) + '...';
          
          findings.push({
            title: `Exposed ${pattern.name} in Client-Side Code`,
            severity: pattern.severity,
            category: 'DAST Audit',
            description: `A ${pattern.name} (${sanitizedMatch}) was found embedded in the HTML source code. Secret keys and tokens in client-side code can be extracted by anyone viewing the page source.`,
            impact: `${pattern.severity === 'critical' ? 'Critical' : 'High'}. Attackers can extract this credential and use it to authenticate against third-party APIs, access cloud resources, or escalate privileges.`,
            solution: `Immediately revoke the exposed ${pattern.name}. Move all secret keys to a secure backend environment. Never include secrets in client-side code, HTML, or JavaScript bundles.`,
            fileName: `HTML Response: ${targetUrl}`,
            originalCode: `// Secret found in source:\n${matches[0]}`,
            fixedCode: `// Fetch data from secure backend endpoint\nconst data = await fetch('/api/secure-route', {\n  headers: { 'Authorization': 'Bearer <server-side-token>' }\n});`,
            remediated: false,
            remediationType: 'code'
          });
        }
      }

      // 5. Technology Fingerprinting
      for (const tech of TECH_FINGERPRINTS) {
        if (tech.test(html)) {
          let version = null;
          if (tech.extractVersion) {
            version = tech.extractVersion(html);
          }

          const techName = version ? `${tech.name} ${version}` : tech.name;
          metadata.technologies.push(techName);

          // Only flag concerning technologies (not just presence detection)
          if (tech.severity === 'medium') {
            findings.push({
              title: `${tech.name} Detected in Production`,
              severity: 'medium',
              category: 'DAST Audit',
              description: `${tech.name} was detected in the production build. ${tech.name === 'Webpack Dev Server' ? 'The Webpack Dev Server should never run in production as it exposes hot-module-replacement endpoints and internal build details.' : tech.name === 'Source Map Reference' ? 'Source maps expose the original unminified source code, allowing attackers to study the application logic, find vulnerabilities, and extract hardcoded secrets.' : 'This development tool should be disabled in production.'}`,
              impact: 'Medium. Development tools in production expose internal implementation details and may provide additional attack vectors.',
              solution: `${tech.name === 'Source Map Reference' ? 'Remove source map references from production builds. In Webpack: set devtool to false or use hidden-source-map.' : 'Ensure development tools and debug modes are disabled in your production build configuration.'}`,
              fileName: `HTML Response: ${targetUrl}`,
              originalCode: `// ${tech.name} detected in production build`,
              fixedCode: `// ${tech.name} removed from production configuration`,
              remediated: false,
              remediationType: 'config'
            });
          }
        }
      }

      // 6. Check for HTML comments containing sensitive information
      const sensitiveCommentPatterns = [
        { regex: /<!--\s*(?:TODO|FIXME|HACK|BUG|XXX)[:\s].*?-->/gi, name: 'Developer Comment (TODO/FIXME)' },
        { regex: /<!--\s*(?:password|secret|key|token|credential|api.?key)[:\s=].*?-->/gi, name: 'Sensitive Data in Comment' },
        { regex: /<!--\s*(?:staging|development|debug|test)\s.*?-->/gi, name: 'Environment Information in Comment' }
      ];

      for (const commentPattern of sensitiveCommentPatterns) {
        const commentMatches = html.match(commentPattern.regex);
        if (commentMatches && commentMatches.length > 0) {
          const sanitized = commentMatches[0].length > 80 ? commentMatches[0].substring(0, 80) + '...' : commentMatches[0];
          findings.push({
            title: `${commentPattern.name} Found in HTML`,
            severity: commentPattern.name.includes('Sensitive') ? 'medium' : 'low',
            category: 'DAST Audit',
            description: `An HTML comment containing potentially sensitive information was found: "${sanitized}". HTML comments are visible to anyone viewing the page source.`,
            impact: `${commentPattern.name.includes('Sensitive') ? 'Medium' : 'Low'}. HTML comments can leak internal development details, credentials, or architectural information to attackers.`,
            solution: 'Remove all development comments from production HTML. Use a build step to strip HTML comments before deployment.',
            fileName: `HTML Response: ${targetUrl}`,
            originalCode: sanitized,
            fixedCode: `<!-- All development comments stripped in production -->`,
            remediated: false,
            remediationType: 'code'
          });
        }
      }

      // 7. Check for inline JavaScript error handlers that leak info
      if (html.includes('window.onerror') || html.includes('addEventListener(\'error\'')) {
        // Check if error handler sends data to a different domain
        const errorHandlerMatch = html.match(/window\.onerror\s*=\s*function[^}]+}/);
        if (errorHandlerMatch && /https?:\/\/(?!.*(?:sentry|bugsnag|rollbar|datadog))/.test(errorHandlerMatch[0])) {
          findings.push({
            title: 'Suspicious Error Handler Sending Data to External Domain',
            severity: 'medium',
            category: 'DAST Audit',
            description: 'A global error handler was detected that appears to send error data to an unrecognized external domain. This could be a legitimate error tracking service or a malicious data exfiltration script.',
            impact: 'Medium. Error data often contains stack traces, user state, and URL parameters that could be sensitive.',
            solution: 'Verify the error handler destination is a trusted error tracking service. Remove any unrecognized error reporting endpoints.',
            fileName: `HTML Response: ${targetUrl}`,
            originalCode: errorHandlerMatch[0].substring(0, 100),
            fixedCode: `// Use a trusted error tracking service\n// window.onerror = Sentry.captureException`,
            remediated: false,
            remediationType: 'code'
          });
        }
      }
    }
  } catch (err) {
    metadata.error = err.message;
  }

  metadata.endTime = new Date().toISOString();
  metadata.findingsCount = findings.length;
  return { findings, metadata };
}

module.exports = { scanCMS };
