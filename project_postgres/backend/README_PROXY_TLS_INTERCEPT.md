# HTTPS Proxy Interception Readiness

This project now includes the first readiness pieces for full HTTPS interception (MITM), but not the final interception pipeline itself.

What is implemented now:

- Config flags for TLS interception readiness in the proxy health payload.
- A local CA generator script:
  - `cd db`
  - `python generate_proxy_ca.py`
- Proxy-side static URL/domain scanning still happens before forwarding.
- Proxy audit persistence can be synchronous, so users feel the scan path before the request continues.
- A configurable artificial scan delay can be added to make the filtering path feel realistic.

Why full HTTPS interception is not fully enabled yet:

- A forward proxy only sees `CONNECT host:443` unless it performs TLS interception.
- Full encrypted URL/path inspection requires:
  - a trusted root CA installed on every client device
  - dynamic leaf certificate generation per destination host
  - a TLS server context between client and proxy
  - a second TLS client connection from proxy to destination
  - request parsing inside the decrypted tunnel

Suggested next implementation steps:

1. Generate and store the local CA with `generate_proxy_ca.py`.
2. Add dynamic per-host leaf certificate generation and caching.
3. Upgrade the `CONNECT` path so the proxy terminates client TLS locally.
4. Parse decrypted HTTP requests inside the tunnel.
5. Reuse `_evaluate_url_static(...)` on the full HTTPS URL before forwarding upstream.
6. Install the generated CA certificate on every managed client.

Recommended environment variables:

```env
SECA_PROXY_TLS_INTERCEPT=false
SECA_PROXY_TLS_CA_CERT_PATH=C:\path\to\seca_proxy_ca.crt
SECA_PROXY_TLS_CA_KEY_PATH=C:\path\to\seca_proxy_ca.key
SECA_PROXY_STATIC_SCAN_DELAY_MS=400
SECA_PROXY_STATIC_AUDIT_SYNC=true
```

Important limitation:

- Without full TLS interception, HTTPS filtering is still host/domain based, not full path/query based.
