# OWASP Compliance Dashboard

This project provides a Cloudflare Worker and frontend dashboard to check OWASP Top 10 compliance for your Cloudflare zones. It uses the Cloudflare API to fetch zone settings and security features, and displays compliance results in a modern, interactive UI.

## Local Development

1. Clone the repository.
2. Create a `.dev.vars` file in the root with your Cloudflare API token and account ID:
   ```
   API_TOKEN="your-cloudflare-api-token"
   ACCOUNT_ID="your-cloudflare-account-id"
   ```
3. Run the Worker locally:
   ```sh
   npx wrangler dev
   ```
4. Open the dashboard at [http://localhost:8787](http://localhost:8787)

## Deploy to Cloudflare

- Click the button below to deploy this project to your Cloudflare account.
- Setup API token and account ID under Dashboard > Settings > Variables and Secrets

<a href="https://deploy.workers.cloudflare.com/?url=https://github.com/iamask/owasp-compliance-dashboard"><img src="https://deploy.workers.cloudflare.com/button" alt="Deploy to Cloudflare"/></a>

## References

- [Cloudflare API Docs](https://developers.cloudflare.com/api/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)

## OWASP Categories & Cloudflare Checks

This dashboard checks the following Cloudflare features for OWASP Top 10 compliance. Each check is mapped to a specific Cloudflare API endpoint and compliance logic:

**Broken Access Control**

- **Custom Rules for URL paths or methods**: Checks for custom firewall rules restricting access to specific paths or HTTP methods.
- **WAF Signatures**: Verifies that managed WAF signatures are enabled to block known attack patterns.
- **Access Rules / Firewall Rules**: Ensures IP, ASN, or country-based access rules are configured.

**Cryptographic Failures**

- **HSTS**: Confirms HTTP Strict Transport Security is enabled to enforce HTTPS.
- **Minimum TLS Version 1.2**: Ensures the minimum TLS version is set to 1.2 or higher.
- **Minimum TLS Version 1.3**: Ensures TLS 1.3 is enabled for maximum security.
- **Always Use HTTPS**: Checks that HTTP requests are automatically redirected to HTTPS.
- **ECDHE Cipher Suites**: Verifies that at least one ECDHE cipher suite is enabled for forward secrecy.
- **Universal SSL**: Confirms Universal SSL is enabled for automatic certificate provisioning.
- **Edge Certificates**: Ensures at least one active, non-expired edge certificate is present.

**Injection**

- **WAF Signatures**: Verifies that managed WAF signatures are enabled to block injection attacks.
- **WAF ML**: Checks for machine learning-based WAF rules to detect advanced threats.
- **WAF Custom Rules (regex validation)**: Ensures custom WAF rules using regex are in place to block malicious input.

**Insecure Design**

- **WAF Signatures**: Verifies that managed WAF signatures are enabled to block insecure design exploits.
- **WAF ML**: Checks for machine learning-based WAF rules to detect insecure design patterns.
- **WAF Custom Rules (regex validation)**: Ensures custom WAF rules using regex are in place for design-related threats.
- **Bot Management**: Checks for rules leveraging Cloudflare Bot Management to mitigate automated threats.
- **Rate Limiting**: Ensures rate limiting rules are configured to prevent abuse.

**Security Misconfiguration**

- **WAF Custom Rules**: Checks for custom WAF rules to address misconfigurations.
- **Automatic HTTPS Rewrites**: Ensures automatic rewriting of HTTP links to HTTPS.
- **Always Use HTTPS**: Checks that HTTP requests are automatically redirected to HTTPS.
- **Page Rules**: Verifies page rules are set, especially for HTTP to HTTPS redirects.
- **Zone Lockdown**: Ensures zone lockdown rules are present to restrict sensitive endpoints.

**Vulnerable and Outdated Components**

- **WAF ML**: Checks for machine learning-based WAF rules to detect vulnerabilities.
- **Transform Rules**: Ensures response header transform rules are configured to mitigate outdated components.

**Identification and Authentication Failures**

- **WAF Custom Rules**: Checks for custom WAF rules to address authentication weaknesses.

**Software and Data Integrity Failures**

- **WAF ML**: Checks for machine learning-based WAF rules to detect integrity issues.
- **WAF Signatures**: Verifies that managed WAF signatures are enabled for integrity protection.
- **Page Shield**: Ensures Page Shield is enabled to monitor for malicious scripts.
- **Signed Exchanges**: Checks if signed exchanges (AMP SXG) are enabled for content integrity.

**Security Logging and Monitoring Failures**

- **Log Push**: Ensures Logpush jobs are configured to export HTTP request logs for monitoring.

**Server-Side Request Forgery (SSRF)**

- **WAF Signatures**: Verifies that managed WAF signatures are enabled to block SSRF attacks.
- **WAF Custom Rules (regex validation)**: Ensures custom WAF rules using regex are in place to block SSRF attempts.

---

For features without a dedicated compliance function, the dashboard checks if the Cloudflare API reports the feature as enabled or successful.

MIT License
