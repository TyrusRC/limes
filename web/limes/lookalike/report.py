"""The abuse-report text for a lookalike. Text only: Limes never contacts a registrar or registrant; the user sends it.
Every value is stored third-party data, so control characters are stripped and lengths capped before it is placed."""
from limes.lookalike.check import defang  # noqa: F401 - re-exported: titles and reports share one defanging rule
from limes.lookalike.rdap import CTRL


def _t(value, limit=200):
    return CTRL.sub(' ', str(value if value is not None else '')).strip()[:limit]


def _list(values):
    return ', '.join(_t(v, 253) for v in (values or [])[:10]) or 'none'


def abuse_report(row, user):
    rdap, dns, ct, web = row.rdap or {}, row.dns or {}, row.ct or {}, row.http
    registrar, abuse = _t(rdap.get('registrar')), _t(rdap.get('abuse_email'))
    reporter = _t(user.get_full_name() or user.username)
    lines = [
        'To the abuse desk,', '',
        'I am reporting a domain that imitates a brand domain we own, and ask that you investigate it.', '',
        f'Our domain: {_t(row.root.value, 253)}',
        f'Lookalike (punycode): {_t(row.domain, 253)}',
        f'Lookalike (unicode): {_t(row.unicode, 253)}',
        f'How it resembles ours: {_list(row.fuzzers)}',
        f'Registrar: {registrar or "unknown"}',
        f'Created: {_t(rdap.get("created")) or "unknown"}',
        f'Name servers: {_list(dns.get("ns"))}',
        f'A records: {_list(dns.get("a"))}',
        f'Mail (MX): {_list(dns.get("mx"))}',
    ]
    if ct.get('certs'):
        lines.append('Certificates seen in Certificate Transparency: ' + ', '.join(
            f'crt.sh id {int(c["id"])} ({_t(c.get("date"), 10) or "date unknown"})' for c in ct['certs'][:10] if isinstance(c.get('id'), int)))
    if web:
        lines.append(f'Web page observed {_t(web.get("checked_at"), 32)}: HTTP status {_t(web.get("status"), 6) or "none"}, title '
                     f'"{_t(web.get("title"))}", login form: {"yes" if web.get("password_field") else "no"}, '
                     f'mentions our brand: {"yes" if web.get("brand_in_page") else "no"}')
    lines += ['', 'Reporter:', f'  {reporter}', f'  {_t(user.email)}', f'  {_t(row.project.name)}']
    return {'to': abuse or registrar, 'subject': f'Abuse report: domain {_t(row.domain, 253)} impersonates {_t(row.root.value, 253)}',
            'body': '\n'.join(lines) + '\n'}
