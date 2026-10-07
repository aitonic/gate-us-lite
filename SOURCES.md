# Design and source references

This project is an original lightweight implementation informed by the public behavior and documentation of:

- VPN Gate CSV API: https://www.vpngate.net/api/iphone/
- VPNGateSub: https://github.com/HXinTeam/VPNGateSub -- OpenVPN-to-Mihomo field mapping and standard-library approach.
- gatevpn: https://github.com/illria/gatevpn -- multi-source idea and IP-risk lessons.
- Vpngate-Scraper-API: https://github.com/fdciabdul/Vpngate-Scraper-API -- VPNGate-family recovery source and historical snapshots.
- CFNext: https://github.com/PAICNI/CFNext -- VPN Gate operational lessons: low-count snapshot protection, last-good cache fallback, tolerant Base64 profile location, pre-filter-before-materialization, and lightweight TCP reachability signals. Its Cloudflare tunnel architecture and TCP-only constraint are intentionally not copied here.
- PublicVPNList API: https://publicvpnlist.com/api/, https://publicvpnlist.com/api/protocols/openvpn/ and the OpenAPI contract https://publicvpnlist.com/api/openapi.json (24-hour keys, nullable `config_download_url`).
- Mihomo OpenVPN configuration: https://wiki.metacubex.one/en/config/proxies/openvpn/
- Mihomo fallback groups: https://wiki.metacubex.one/en/config/proxy-groups/fallback/
- GitHub scheduled workflows: https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows
- GitHub Actions used by the workflow, pinned to the commit SHAs behind these tags: `actions/checkout@v7`, `actions/setup-python@v7`, `actions/cache/restore@v6`, `actions/cache/save@v6`, `actions/upload-artifact@v7`, `actions/download-artifact@v8` (refs API: https://docs.github.com/en/rest/git/refs).
- ProxyCheck v3 API (response sections, risk score, `days` flag, status codes): https://proxycheck.io/api/
- AbuseIPDB `check` endpoint (`usageType`, `isTor`): https://docs.abuseipdb.com/#check-endpoint
- ipapi.is free tier (evaluated, not used): https://ipapi.is/free-tier.html

No third-party repository is vendored into this package. Network profiles are treated as untrusted input and normalized through an allow-list before Mihomo YAML is generated.
