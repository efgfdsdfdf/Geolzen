const nodemailer = require('nodemailer');

let testAccount = null;
let transporter = null;

async function initMailer() {
  if (!transporter) {
    try {
      // Generate a test ethereal account
      testAccount = await nodemailer.createTestAccount();
      
      // Create a transporter object
      transporter = nodemailer.createTransport({
        host: 'smtp.ethereal.email',
        port: 587,
        secure: false, // true for 465, false for other ports
        auth: {
          user: testAccount.user,
          pass: testAccount.pass
        }
      });
      console.log(`[MAILER] Ethereal test account created: ${testAccount.user}`);
    } catch (err) {
      console.error('[MAILER ERROR] Failed to initialize ethereal mailer:', err);
    }
  }
}

/**
 * Send a vulnerability report email
 * @param {string} toEmail 
 * @param {string} targetName 
 * @param {Array} findings 
 * @returns {Promise<string>} URL to view the email
 */
async function sendVulnerabilityAlert(toEmail, targetName, findings) {
  if (!transporter) {
    await initMailer();
  }

  if (!transporter) {
    throw new Error('Mailer not initialized');
  }

  // Count severities
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  findings.forEach(f => {
    if (counts[f.severity] !== undefined) {
      counts[f.severity]++;
    }
  });

  const criticalHighList = findings
    .filter(f => f.severity === 'critical' || f.severity === 'high')
    .map(f => `<li><strong>[${f.severity.toUpperCase()}]</strong> ${f.title}</li>`)
    .join('');

  const htmlContent = `
    <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto; color: #333;">
      <h2 style="color: #d93025;">Geolzen Security Alert</h2>
      <p>A recent scan of your target <strong>${targetName}</strong> has discovered vulnerabilities that require your attention.</p>
      
      <div style="background-color: #f8f9fa; padding: 15px; border-radius: 8px; margin-bottom: 20px;">
        <h3>Scan Summary</h3>
        <ul style="list-style-type: none; padding-left: 0;">
          <li><strong>Critical:</strong> ${counts.critical}</li>
          <li><strong>High:</strong> ${counts.high}</li>
          <li><strong>Medium:</strong> ${counts.medium}</li>
          <li><strong>Low:</strong> ${counts.low}</li>
        </ul>
      </div>

      ${criticalHighList ? `
      <h3>Action Required</h3>
      <p>The following high-priority issues were identified:</p>
      <ul>
        ${criticalHighList}
      </ul>
      ` : '<p>No critical or high vulnerabilities were found.</p>'}
      
      <p style="margin-top: 30px;">
        <a href="https://geolzen.com/login" style="background-color: #2b30ff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block;">
          View Full Details in Dashboard
        </a>
      </p>
      
      <hr style="border: 0; border-top: 1px solid #eee; margin-top: 40px;">
      <p style="font-size: 12px; color: #777;">
        This is an automated security alert from Geolzen Autonomous Security Platform.
      </p>
    </div>
  `;

  const info = await transporter.sendMail({
    from: '"Geolzen Security Agent" <security@geolzen.com>',
    to: toEmail || 'security-team@sandbox.com',
    subject: `🚨 Security Alert: ${counts.critical + counts.high} Actionable Findings on ${targetName}`,
    text: `Geolzen found vulnerabilities on ${targetName}. View your dashboard for details.`,
    html: htmlContent
  });

  const previewUrl = nodemailer.getTestMessageUrl(info);
  console.log(`[MAILER] Alert sent! View it here: ${previewUrl}`);
  return previewUrl;
}

module.exports = {
  sendVulnerabilityAlert
};
