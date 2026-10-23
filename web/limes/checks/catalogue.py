"""Risk-check catalogue: ids, groups, severities and wording. Pure data, no I/O."""
from collections import namedtuple

Check = namedtuple('Check', 'id group severity title fix provisional', defaults=(False,))
Result = namedtuple('Result', 'check status evidence')

STATUSES = ('pass', 'fail', 'error', 'not_applicable')

# port -> (service, severity); each yields a net.exposed_<service> check
RISKY_PORTS = {
    21: ('ftp', 2), 23: ('telnet', 3), 445: ('smb', 3), 3389: ('rdp', 3), 1433: ('mssql', 3),
    1521: ('oracle', 3), 3306: ('mysql', 3), 5432: ('postgres', 3), 6379: ('redis', 3),
    9200: ('elasticsearch', 3), 11211: ('memcached', 3), 27017: ('mongodb', 3),
    2375: ('docker', 3), 5900: ('vnc', 3),
}

_STATIC = [
    ('web.https_missing', 'web', 3, 'The site answers over HTTP but not over HTTPS.',
     'Serve the site over HTTPS with a valid certificate.'),
    ('web.http_no_redirect', 'web', 2, 'HTTP requests are not redirected to HTTPS.',
     'Redirect all HTTP requests to the HTTPS version of the same host.'),
    ('web.hsts_missing', 'web', 2, 'The HTTPS site does not send a Strict-Transport-Security header.',
     'Send Strict-Transport-Security with a long max-age on all HTTPS responses.'),
    ('web.csp_missing', 'web', 1, 'The site does not send a Content-Security-Policy header.',
     'Define a Content-Security-Policy that limits where scripts and other content may load from.'),
    ('web.frame_options_missing', 'web', 1, 'The site can be framed by other sites (no X-Frame-Options or frame-ancestors).',
     'Send X-Frame-Options or a CSP frame-ancestors directive to restrict framing.'),
    ('web.content_type_options_missing', 'web', 1, 'The site does not send X-Content-Type-Options: nosniff.',
     'Send the header X-Content-Type-Options: nosniff on all responses.'),
    ('web.cookie_flags_missing', 'web', 1, 'A cookie is set without the Secure, HttpOnly or SameSite attribute.',
     'Set Secure, HttpOnly and SameSite on every cookie.'),
    ('web.version_disclosure', 'web', 1, 'The Server or X-Powered-By header discloses a software version.',
     'Remove version numbers from the Server and X-Powered-By headers.'),
    ('tls.cert_expired', 'tls', 3, 'The TLS certificate has expired.',
     'Renew the certificate and deploy it.'),
    ('tls.cert_expiring', 'tls', 2, 'The TLS certificate expires within 14 days.',
     'Renew the certificate before it expires, ideally with automatic renewal.'),
    ('tls.cert_hostname_mismatch', 'tls', 3, 'The TLS certificate does not match the hostname.',
     'Issue a certificate that covers this hostname.'),
    ('tls.cert_untrusted', 'tls', 3, 'The TLS certificate is self-signed or not trusted by common root stores.',
     'Install a certificate issued by a trusted certificate authority, including the intermediate chain.'),
    ('tls.legacy_protocol', 'tls', 2, 'The server still accepts TLS 1.0 or 1.1.',
     'Disable TLS 1.0 and 1.1 and allow only TLS 1.2 or newer.'),
    ('email.spf_missing', 'email', 2, 'The domain has no SPF record.',
     'Publish an SPF TXT record listing the servers allowed to send mail for the domain.'),
    ('email.spf_permissive', 'email', 2, 'The SPF record ends with +all or ?all, so it allows any sender.',
     'End the SPF record with -all or ~all.'),
    ('email.dmarc_missing', 'email', 2, 'The domain has no DMARC record.',
     'Publish a DMARC TXT record at _dmarc.<domain>.'),
    ('email.dmarc_none', 'email', 1, 'The DMARC policy is p=none, so spoofed mail is not blocked.',
     'Move the DMARC policy to quarantine or reject once reports look clean.'),
    ('email.mx_unprotected', 'email', 1, 'The domain receives mail but lacks SPF or DMARC.',
     'Publish both SPF and DMARC records for the domain.'),
    ('dns.dnssec_missing', 'dns', 1, 'The domain has no DNSSEC (no DS record).',
     'Enable DNSSEC at the DNS provider and publish the DS record at the registrar.'),
    ('dns.caa_missing', 'dns', 1, 'The domain has no CAA record restricting certificate issuance.',
     'Publish CAA records naming the certificate authorities allowed to issue for the domain.'),
]

CHECKS = {i: Check(i, g, s, t, f) for i, g, s, t, f in _STATIC}
for _svc, _sev in RISKY_PORTS.values():
    _id = f'net.exposed_{_svc}'
    CHECKS[_id] = Check(_id, 'network', _sev, f'{_svc} is reachable from the internet on an owned IP address.',
                        f'Close the {_svc} port to the internet or restrict it with a firewall or VPN.')


# Provisional checks: visible, tracked as issues and able to alert, but they cost no points and never make an
# asset "assessed" (scoring.points / scoring.assessed_assets). This table is the ONE place that declares them.
_PROVISIONAL = [
    ('rep.listed_drop', 'reputation', 3, 'The address is inside a network range on the Spamhaus DROP list.',
     'Ask the network provider why the range is listed and have it delisted, or move off it.'),
    ('rep.listed_asndrop', 'reputation', 3, 'The address belongs to an autonomous system on the Spamhaus ASN-DROP list.',
     'Ask the network provider why the AS is listed and have it delisted, or move off it.'),
    ('rep.listed_c2', 'reputation', 4, 'The address is listed as a botnet command-and-control server by Feodo Tracker.',
     'Treat the host as compromised: isolate it, find the malware and rebuild from a clean image.'),
    ('rep.listed_attacker', 'reputation', 2, 'The address appears on a public list of attacking hosts.',
     'Look for a compromised service on the host, clean it up and request delisting.'),
    ('rep.dnsbl_listed', 'reputation', 2, 'The address is listed on a DNS blocklist.',
     'Find the cause (open relay, compromised host), fix it and request delisting from the list.'),
    ('net.exposed_ollama', 'network', 3, 'An Ollama model server is reachable from the internet on an owned IP address.',
     'Bind the Ollama API to localhost or put it behind authentication and a firewall.'),
    ('net.exposed_openai_api', 'network', 3, 'An OpenAI-compatible model API is reachable from the internet on an owned IP address.',
     'Require an API key and restrict the API to trusted networks.'),
    ('net.exposed_triton', 'network', 2, 'A Triton inference server is reachable from the internet on an owned IP address.',
     'Restrict the Triton ports to trusted networks or put them behind an authenticating proxy.'),
    ('net.exposed_gradio', 'network', 2, 'A Gradio app is reachable from the internet on an owned IP address.',
     'Put the Gradio app behind authentication or restrict it to trusted networks.'),
    ('net.exposed_jupyter', 'network', 4, 'A Jupyter server is reachable from the internet on an owned IP address.',
     'Require a token or password, bind Jupyter to localhost and reach it through a VPN or SSH tunnel.'),
    ('net.exposed_ray', 'network', 4, 'A Ray dashboard is reachable from the internet on an owned IP address.',
     'Never expose the Ray dashboard: bind it to localhost and reach it through a VPN or SSH tunnel.'),
    ('leak.supabase_secret_key', 'data_leakage', 4, 'A Supabase secret (service_role) key is served in the site JavaScript.',
     'Revoke and rotate the key in Supabase and keep it server-side only.'),
    ('leak.hibp_breach', 'data_leakage', 2, 'Addresses on the domain appear in a public data breach.',
     'Force password resets for the affected accounts and enable multi-factor authentication.'),
]
for _i, _g, _s, _t, _f in _PROVISIONAL:
    CHECKS[_i] = Check(_i, _g, _s, _t, _f, True)
PROVISIONAL = frozenset(i for i, *_ in _PROVISIONAL)
