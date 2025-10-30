// Cloudflare Account and API Token

// OWASP Top 10 Categories and related Cloudflare features
const owaspCategories = {
  'Broken Access Control': [
    { name: 'Custom Rules for URL paths or methods', apiEndpoint: '/rulesets/phases/http_request_firewall_custom/entrypoint' },
    { name: 'WAF Signatures', apiEndpoint: '/rulesets/phases/http_request_firewall_managed/entrypoint' },
    { name: 'Access Rules / Firewall Rules', apiEndpoint: '/firewall/access_rules/rules' },
  ],
  'Cryptographic Failures': [
    { name: 'HSTS', apiEndpoint: '/settings/security_header' },
    { name: 'Minimum TLS Version 1.2', apiEndpoint: '/settings' },
    { name: 'Minimum TLS Version 1.3', apiEndpoint: '/settings' },
    { name: 'Always Use HTTPS', apiEndpoint: '/settings' },
    { name: 'ECDHE Cipher Suites', apiEndpoint: '/settings' },
    { name: 'Universal SSL', apiEndpoint: '/ssl/universal/settings' },
    // Use correct API for certificate packs: https://developers.cloudflare.com/api/operations/certificate-packs-for-a-zone-list-certificate-packs
    { name: 'Edge Certificates', apiEndpoint: '/ssl/certificate_packs' },
  ],
  'Injection': [
    { name: 'WAF Signatures', apiEndpoint: '/rulesets/phases/http_request_firewall_managed/entrypoint' },
    { name: 'WAF ML', apiEndpoint: '/rulesets/phases/http_request_firewall_custom/entrypoint' },
    { name: 'WAF Custom Rules (regex validation)', apiEndpoint: '/rulesets/phases/http_request_firewall_custom/entrypoint' },
  ],
  'Insecure Design': [
    { name: 'WAF Signatures', apiEndpoint: '/rulesets/phases/http_request_firewall_managed/entrypoint' },
    { name: 'WAF ML', apiEndpoint: '/rulesets/phases/http_request_firewall_custom/entrypoint' },
    { name: 'WAF Custom Rules (regex validation)', apiEndpoint: '/rulesets/phases/http_request_firewall_custom/entrypoint' },
    { name: 'Bot Management', apiEndpoint: '/rulesets/phases/http_request_firewall_custom/entrypoint' },
    // Use correct API for rate limiting: https://developers.cloudflare.com/api/operations/rulesets-for-a-zone-list-phase-entrypoint-rulesets
    { name: 'Rate Limiting', apiEndpoint: '/rulesets/phases/http_ratelimit/entrypoint' },
  ],
  'Security Misconfiguration': [
    { name: 'WAF Custom Rules', apiEndpoint: '/rulesets/phases/http_request_firewall_custom/entrypoint' },
    { name: 'Automatic HTTPS Rewrites', apiEndpoint: '/settings' },
    { name: 'Always Use HTTPS', apiEndpoint: '/settings' },
    { name: 'Page Rules', apiEndpoint: '/pagerules' },
    { name: 'Zone Lockdown', apiEndpoint: '/zone_lockdown' },
  ],
  'Vulnerable and Outdated Components': [
    { name: 'WAF ML', apiEndpoint: '/rulesets/phases/http_request_firewall_custom/entrypoint' },
    { name: 'Transform Rules', apiEndpoint: '/rulesets/phases/http_response_headers_transform/entrypoint' },
  ],
  'Identification and Authentication Failures': [
    { name: 'WAF Custom Rules', apiEndpoint: '/rulesets/phases/http_request_firewall_custom/entrypoint' },
  ],
  'Software and Data Integrity Failures': [
    { name: 'WAF ML', apiEndpoint: '/rulesets/phases/http_request_firewall_custom/entrypoint' },
    { name: 'WAF Signatures', apiEndpoint: '/rulesets/phases/http_request_firewall_managed/entrypoint' },
    { name: 'Page Shield', apiEndpoint: '/page_shield' },
,
  ],
  'Security Logging and Monitoring Failures': [
    { name: 'Log Push', apiEndpoint: '/logpush/jobs' },
  ],
  'Server-Side Request Forgery (SSRF)': [
    { name: 'WAF Signatures', apiEndpoint: '/rulesets/phases/http_request_firewall_managed/entrypoint' },
    { name: 'WAF Custom Rules (regex validation)', apiEndpoint: '/rulesets/phases/http_request_firewall_custom/entrypoint' },
  ],
};

export default {
  async fetch(request, env, ctx) {
    const urlObj = new URL(request.url);
    const apiToken = env.API_TOKEN;
    const accountId = env.ACCOUNT_ID;

    // --- List Zones Endpoint ---
    if (urlObj.pathname === '/api/listzones') {
      const url = `https://api.cloudflare.com/client/v4/zones?account.id=${accountId}`;
      console.log('Calling Cloudflare API:', url);
      if (!apiToken) {
        console.log('Missing API token');
        return new Response(JSON.stringify({ error: 'Missing API token' }), {
          status: 500,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      const headers = {
        'Authorization': `Bearer ${apiToken}`,
        'Content-Type': 'application/json',
      };
      let data;
      try {
        const response = await fetch(url, { headers });
        console.log('Cloudflare API response status:', response.status);
        if (!response.ok) {
          const text = await response.text();
          console.log('Cloudflare API error response:', text);
          throw new Error(`HTTP error! Status: ${response.status} - ${text}`);
        }
        data = await response.json();
        console.log('Cloudflare API data:', data);
      } catch (error) {
        console.log('API request failed:', error.message, error.stack);
        return new Response(JSON.stringify({ error: 'API request failed', details: error.message, stack: error.stack }), {
          status: 500,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      if (!data.success) {
        console.log('Cloudflare API returned unsuccessful response:', data);
        return new Response(JSON.stringify({ error: 'Failed to fetch zones', apiResponse: data }), {
          status: 500,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      const activeZones = data.result.map(zone => ({ id: zone.id, name: zone.name }));
      console.log('Returning activeZones:', activeZones);
      return new Response(JSON.stringify({ activeZones }), {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
        },
      });
    }

    // --- OWASP Compliance Endpoint ---
    if (urlObj.pathname.startsWith('/api/owasp')) {
      const zoneId = urlObj.searchParams.get('zone_id');
      if (!zoneId) {
        return new Response('Missing zone_id query parameter', { status: 400 });
      }
      const apiBaseUrl = `https://api.cloudflare.com/client/v4/zones/${zoneId}`;
      const headers = {
        'Authorization': `Bearer ${apiToken}`,
        'Content-Type': 'application/json',
      };
      const results = {};
      for (const [category, features] of Object.entries(owaspCategories)) {
        const featureResults = await Promise.all(features.map(async (feature) => {
          console.log(`[OWASP CHECK] Category: ${category}, Feature: ${feature.name}, Endpoint: ${feature.apiEndpoint}`);
          try {
            const response = await fetch(`${apiBaseUrl}${feature.apiEndpoint}`, {
              method: 'GET',
              headers,
            });
            const data = await response.json();
            let complianceResult;
            switch (feature.name) {
              case 'WAF Signatures':
                complianceResult = WAFsignature_checkCompliance(data, feature);
                break;
              case 'Custom Rules for URL paths or methods':
              case 'WAF ML':
              case 'WAF Custom Rules (regex validation)':
                complianceResult = WAFcustom_checkCompliance(data, feature);
                break;
              case 'HSTS':
                complianceResult = HSTS_checkCompliance(data, feature);
                break;
              case 'Page Shield':
                complianceResult = Pagesheild_checkCompliance(data, feature);
                break;
              case 'Log Push':
                complianceResult = Logpush_checkCompliance(data, feature);
                break;
              case 'Bot Management':
                complianceResult = Bot_checkCompliance(data, feature);
                break;
              case 'Minimum TLS Version 1.2':
                complianceResult = MinTlsVersion_checkCompliance(data, feature);
                break;
              case 'Minimum TLS Version 1.3':
                complianceResult = TLSVersion_checkCompliance(data, feature);
                break;
              case 'Always Use HTTPS':
                complianceResult = AlwaysUseHttps_checkCompliance(data, feature);
                break;
              case 'ECDHE Cipher Suites':
                complianceResult = ECDHECipherSuites_checkCompliance(data, feature);
                break;
              case 'Universal SSL':
                complianceResult = UniversalSSL_checkCompliance(data, feature);
                break;
              case 'Edge Certificates':
                complianceResult = EdgeCertificates_checkCompliance(data, feature);
                break;
              case 'Rate Limiting':
                complianceResult = RateLimiting_checkCompliance(data, feature);
                break;
              case 'Page Rules':
                complianceResult = PageRules_checkCompliance(data, feature);
                break;
              case 'Zone Lockdown':
                complianceResult = ZoneLockdown_checkCompliance(data, feature);
                break;
              case 'Transform Rules':
                complianceResult = TransformRules_checkCompliance(data, feature);
                break;
              case 'Signed Exchanges':
                complianceResult = SignedExchanges_checkCompliance(data, feature);
                break;
              default:
                complianceResult = otherCompliance(data, feature);
            }
            return complianceResult;
          } catch (error) {
            return { name: feature.name, enabled: false, complianceStatus: 'Non-Compliant', error: error.message };
          }
        }));
        const categoryCompliant = featureResults.some(result => result.enabled && result.complianceStatus === 'Compliant');
        results[category] = {
          compliant: categoryCompliant,
          features: featureResults,
        };
      }
      return new Response(JSON.stringify(results), {
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // --- 404 for all other requests ---
    return new Response('Not Found', { status: 404 });
  },
};

// --- Compliance Check Functions ---
function WAFsignature_checkCompliance(data, feature) {
  if (data.result && Array.isArray(data.result.rules)) {
    for (const rule of data.result.rules) {
      if (rule.action_parameters && rule.action_parameters.id === 'efb7b8c949ac4650a09736fc376e9aee') {
        if (rule.enabled) {
          return { name: feature.name, enabled: true, complianceStatus: 'Compliant' };
        }
      }
    }
  }
  return { name: feature.name, enabled: false, complianceStatus: 'Non-Compliant' };
}

function WAFcustom_checkCompliance(data, feature) {
  if (data.result && Array.isArray(data.result.rules)) {
    for (const rule of data.result.rules) {
      if (rule.action === 'log' || rule.action === 'block') {
        return { name: feature.name, enabled: true, complianceStatus: 'Compliant' };
      }
    }
  }
  return { name: feature.name, enabled: false, complianceStatus: 'Non-Compliant' };
}

function HSTS_checkCompliance(data, feature) {
  if (data.result && data.result.value && data.result.value.strict_transport_security) {
    const hstsConfig = data.result.value.strict_transport_security;
    const enabled = hstsConfig.enabled;
    const complianceStatus = enabled ? 'Compliant' : 'Non-Compliant';
    return { name: feature.name, enabled, complianceStatus };
  }
  console.error('Unexpected response structure or missing strict_transport_security:', data);
  return { name: feature.name, enabled: false, complianceStatus: 'Non-Compliant' };
}

function Pagesheild_checkCompliance(data, feature) {
  if (data.result && typeof data.result.enabled !== 'undefined') {
    const enabled = data.result.enabled;
    const complianceStatus = enabled ? 'Compliant' : 'Non-Compliant';
    return { name: feature.name, enabled, complianceStatus };
  }
  console.error('Unexpected response structure or missing "enabled" property:', data);
  return { name: feature.name, enabled: false, complianceStatus: 'Non-Compliant' };
}

function Logpush_checkCompliance(data, feature) {
  if (data.result && Array.isArray(data.result)) {
    const httpRequestDataset = data.result.find(dataset => dataset.dataset === 'http_requests');
    if (httpRequestDataset && typeof httpRequestDataset.enabled !== 'undefined') {
      const enabled = httpRequestDataset.enabled;
      const complianceStatus = enabled ? 'Compliant' : 'Non-Compliant';
      return { name: feature.name, enabled, complianceStatus };
    } else {
      console.error('Dataset object not found or missing "enabled" property:', httpRequestDataset);
    }
  } else {
    console.error('Unexpected response structure or missing "result" property:', data);
  }
  return { name: feature.name, enabled: false, complianceStatus: 'Non-Compliant' };
}

function Bot_checkCompliance(data, feature) {
  if (data.result && Array.isArray(data.result.rules)) {
    const containsBotManagementScore = data.result.rules.some(
      rule => rule.expression && rule.expression.includes('cf.bot_management.score')
    );
    const complianceStatus = containsBotManagementScore ? 'Compliant' : 'Non-Compliant';
    return { name: feature.name, compliant: containsBotManagementScore, complianceStatus };
  } else {
    console.error('Unexpected response structure or missing "rules" property:', data);
    return { name: feature.name, compliant: false, complianceStatus: 'Non-Compliant' };
  }
}

function MinTlsVersion_checkCompliance(data, feature) {
  if (Array.isArray(data.result)) {
    const minTlsVersionSetting = data.result.find(setting => setting.id === 'min_tls_version');
    const tls13 = data.result.find(setting => setting.id === 'tls_1_3');
    if (
      (minTlsVersionSetting && minTlsVersionSetting.value === '1.2') ||
      (tls13 && tls13.value === 'on')
    ) {
      return { name: feature.name, compliant: true, complianceStatus: 'Compliant' };
    }
  }
  return { name: feature.name, compliant: false, complianceStatus: 'Non-Compliant' };
}

function TLSVersion_checkCompliance(data, feature) {
  // Looks for min_tls_version or tls_1_3 in /settings
  if (Array.isArray(data.result)) {
    const minTls = data.result.find(s => s.id === 'min_tls_version');
    const tls13 = data.result.find(s => s.id === 'tls_1_3');
    if (minTls && minTls.value === '1.3' && tls13 && tls13.value === 'on') {
      return { name: feature.name, enabled: true, complianceStatus: 'Compliant' };
    }
    if (minTls && minTls.value === '1.3') {
      return { name: feature.name, enabled: true, complianceStatus: 'Compliant' };
    }
    // If min_tls_version is not 1.3, return Non-Compliant
    return { name: feature.name, enabled: false, complianceStatus: 'Non-Compliant' };
  }
  return { name: feature.name, enabled: false, complianceStatus: 'Non-Compliant' };
}

function ECDHECipherSuites_checkCompliance(data, feature) {
  // Checks if at least one ECDHE cipher is enabled
  if (Array.isArray(data.result)) {
    const ciphers = data.result.find(s => s.id === 'ciphers');
    if (ciphers && Array.isArray(ciphers.value)) {
      const hasECDHE = ciphers.value.some(cipher => cipher.startsWith('ECDHE-'));
      if (hasECDHE) {
        return { name: feature.name, enabled: true, complianceStatus: 'Compliant' };
      }
    }
  }
  return { name: feature.name, enabled: false, complianceStatus: 'Non-Compliant' };
}

function UniversalSSL_checkCompliance(data, feature) {
  // Checks if Universal SSL is enabled
  if (data.result && typeof data.result.enabled !== 'undefined') {
    return { name: feature.name, enabled: data.result.enabled, complianceStatus: data.result.enabled ? 'Compliant' : 'Non-Compliant' };
  }
  return { name: feature.name, enabled: false, complianceStatus: 'Non-Compliant' };
}

function EdgeCertificates_checkCompliance(data, feature) {
  // Checks for at least one active, non-expired certificate in any certificate pack
  if (Array.isArray(data.result)) {
    for (const pack of data.result) {
      if (Array.isArray(pack.certificates)) {
        for (const cert of pack.certificates) {
          if (
            cert.status === 'active' &&
            (!cert.expires_on || new Date(cert.expires_on) > new Date())
          ) {
            return { name: feature.name, enabled: true, complianceStatus: 'Compliant' };
          }
        }
      }
    }
    // If there are certificates but none are valid
    if (data.result.some(pack => Array.isArray(pack.certificates) && pack.certificates.length > 0)) {
      return { name: feature.name, enabled: false, complianceStatus: 'Non-Compliant (certificate expired or not active)' };
    }
  }
  return { name: feature.name, enabled: false, complianceStatus: 'Non-Compliant' };
}

function RateLimiting_checkCompliance(data, feature) {
  // Checks if any rate limiting rules exist
  if (data.result && Array.isArray(data.result) && data.result.length > 0) {
    return { name: feature.name, enabled: true, complianceStatus: 'Compliant' };
  }
  return { name: feature.name, enabled: false, complianceStatus: 'Non-Compliant' };
}

function PageRules_checkCompliance(data, feature) {
  // Checks for HTTP to HTTPS redirect rules
  if (data.result && Array.isArray(data.result)) {
    const httpsRule = data.result.find(rule => rule.actions && rule.actions.some(a => a.id === 'forwarding_url' && a.value && a.value.status_code === 301 && a.value.url && a.value.url.startsWith('https://')));
    if (httpsRule) {
      return { name: feature.name, enabled: true, complianceStatus: 'Compliant' };
    }
  }
  return { name: feature.name, enabled: false, complianceStatus: 'Non-Compliant' };
}

function ZoneLockdown_checkCompliance(data, feature) {
  // Checks if any zone lockdown rules exist
  if (data.result && Array.isArray(data.result) && data.result.length > 0) {
    return { name: feature.name, enabled: true, complianceStatus: 'Compliant' };
  }
  return { name: feature.name, enabled: false, complianceStatus: 'Non-Compliant' };
}

function TransformRules_checkCompliance(data, feature) {
  // Checks if any transform rules exist
  if (data.result && Array.isArray(data.result) && data.result.length > 0) {
    return { name: feature.name, enabled: true, complianceStatus: 'Compliant' };
  }
  return { name: feature.name, enabled: false, complianceStatus: 'Non-Compliant' };
}

function SignedExchanges_checkCompliance(data, feature) {
  // Checks if signed exchanges are enabled (AMP SXG)
  if (data.result && data.result.enabled) {
    return { name: feature.name, enabled: true, complianceStatus: 'Compliant' };
  }
  return { name: feature.name, enabled: false, complianceStatus: 'Non-Compliant' };
}

function otherCompliance(data, feature) {
  const enabled = data.success ? true : false;
  const complianceStatus = data.success ? 'Compliant' : 'Non-Compliant';
  return { name: feature.name, enabled, complianceStatus };
}
