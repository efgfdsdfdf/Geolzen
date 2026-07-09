# Geolzen Privacy Policy & User Data Consent

**Effective Date:** July 9, 2026

Geolzen is an autonomous attack surface management and vulnerability remediation platform. Because our core service analyzes, audits, and fixes infrastructure and codebase security, we must collect and process operational metadata. This Privacy Policy details how we acquire, store, and utilize user information.

---

## 1. Information Collected

To perform comprehensive security scans and maintain rules-of-engagement logs, Geolzen collects the following categories of data:

### A. Infrastructure & Domain Scope metadata
- Target Domain Names & IP Addresses.
- Public DNS configuration entries (TXT, MX, A, AAAA records).
- Active open ports and banner-grab version details (e.g. server headers like `nginx/1.18.0`).
- SSL/TLS protocol profiles.

### B. Codebase & Repository Data (SCA/SAST Scope)
- Reference paths to configuration files (e.g., `package.json`, `s3-bucket-policy.json`, `nginx.conf`).
- Library dependency definitions and package versions.
- Static code snippets associated with identified vulnerabilities (e.g. original code vs proposed security patch).

### C. Identity & Legal Compliance Logs
- Signatory Identity: Full legal name, title, and organization.
- Rule of Engagement (ROE) digital signature logs, consent timestamps, and source IP addresses to legally document testing permissions.
- Work credentials: full name, email address, password hashes, and organization name.

### D. User Telemetry & Analyst Chats
- Support Chat logs: direct questions asked to our Security Analyst Copilot.
- Action logs: timestamped actions representing verification checks, scan triggers, and remediation patch applications.

---

## 2. How Data is Utilized

All collected user data is processed to deliver, secure, and optimize Geolzen's core features:
1. **Verification Compliance**: Validating DNS tokens or OAuth credentials to prevent illegal third-party system testing.
2. **Scan Telemetry**: Aggregating open ports, server banners, and software versions to cross-reference against global vulnerability databases (CVE/NVD).
3. **Auto-Remediation Generation**: Processing configuration code to render side-by-side git diff updates and open secure patch pull requests.
4. **Security Copilot Optimization**: Training and tuning our context-aware Security Analyst chatbot to resolve false positives and explain exploits accurately.
5. **Operational Logs**: Displaying active timelines of updates inside the organization dashboard.

---

## 3. Data Storage & Security Controls

Geolzen implements enterprise-grade guardrails to protect sensitive data:
- **Supabase Integration**: Data is stored securely in PostgreSQL databases.
- **Row-Level Security (RLS)**: PostgreSQL RLS policies restrict table records. Users can only query data matching their verified `organization_id`.
- **Encryption Standards**: All communication is conducted over HTTPS using TLS 1.2/1.3. Critical fields (credentials, OAuth tokens, and policies) are encrypted at rest.
- **Data Deletion**: Organizations can request purging target details, scan logs, and profile records at any time.

---

## 4. Consent Affirmation

By registering a Geolzen account, onboarding target infrastructure, and signing the Rules of Engagement (ROE) contract, you explicitly consent to the collection, processing, and storage of operational telemetry as detailed in this policy.
