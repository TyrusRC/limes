"""Registry-level delegation check for attribution auto-confirm (A5a).

A recursive NS answer is the child zone's own claim. This asks the parent (registry) servers
non-recursively who the zone is delegated to, then asks those nameservers - ours - for an
authoritative SOA. Queries go only to registry servers and the delegated nameservers, and never
to a private or reserved address.
"""
from celery.exceptions import SoftTimeLimitExceeded
import dns.exception
import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver

from limes.scope import is_reserved_ip

QUERY_TIMEOUT = 2  # seconds per query
MAX_SERVERS = 2  # servers tried at each stage

# NOTE: the parent is taken as the registrable domain's public suffix. A suffix whose zone cut
# differs from the PSL entry (multi-label registry suffixes, private-suffix tenants such as
# myorg.github.io) fails closed. Upgrade path: walk referrals from the root.
# NOTE: IPv4 only; a nameserver with only AAAA records is unreachable here.


def _norm(name):
    return str(name).rstrip('.').lower()


def _udp_query(qname, rdtype, server_ip):
    q = dns.message.make_query(qname, rdtype, use_edns=0, payload=1232)  # larger referrals fit untruncated
    q.flags &= ~dns.flags.RD
    return dns.query.udp(q, server_ip, timeout=QUERY_TIMEOUT)


def _resolve(name, rdtype):
    try:
        return [_norm(r.to_text()) for r in dns.resolver.resolve(name, rdtype, lifetime=QUERY_TIMEOUT * 2)]
    except dns.exception.DNSException as e:
        # the resolver records each server's exception and retries, Celery's soft time limit included
        for err in (getattr(e, 'kwargs', None) or {}).get('errors') or []:
            if isinstance(err[3], SoftTimeLimitExceeded):
                raise err[3]
        return []


def _addresses(hosts, resolve):
    out = []
    for host in sorted(hosts):
        ips = [ip for ip in resolve(host, 'A') if not is_reserved_ip(ip)]
        if ips:
            out.append((host, ips[0]))
        if len(out) == MAX_SERVERS:
            break
    return out


def _ask(servers, qname, rdtype, query):
    """First answer from the servers in order; timeouts and network errors fall through."""
    for host, ip in servers:
        try:
            return host, query(qname, rdtype, ip)
        except (dns.exception.DNSException, OSError):
            continue
    return None, None


def _rrset(section, owner, rdtype):
    return next((rr for rr in section if rr.rdtype == rdtype and _norm(rr.name) == owner), None)


def verify(domain, control_ns, query=_udp_query, resolve=_resolve):
    """(ok, reason): the registry delegates `domain` to exactly `control_ns`, and one of them
    answers authoritatively (AA) with the zone's SOA. Anything else fails closed."""
    domain = _norm(domain)
    want = tuple(sorted(_norm(h) for h in control_ns))
    suffix = domain.split('.', 1)[1] if '.' in domain else ''
    parents = _addresses(resolve(suffix, 'NS'), resolve) if suffix else []
    if not parents:
        return False, 'no parent servers'
    parent, resp = _ask(parents, domain, 'NS', query)
    if resp is None:
        return False, 'parent unreachable'
    ns = _rrset(resp.authority, domain, dns.rdatatype.NS)
    # a truncated (TC) referral may carry a partial NS set
    if resp.rcode() != dns.rcode.NOERROR or resp.flags & (dns.flags.AA | dns.flags.TC) or ns is None:
        return False, 'no delegation at parent'
    got = tuple(sorted(_norm(r.target) for r in ns))
    if got != want:
        return False, f'parent delegates elsewhere: {", ".join(got)}'
    _, soa = _ask(_addresses(got, resolve), domain, 'SOA', query)
    if soa is None:
        return False, 'nameservers unreachable'
    if soa.rcode() != dns.rcode.NOERROR or not soa.flags & dns.flags.AA or _rrset(soa.answer, domain, dns.rdatatype.SOA) is None:
        return False, 'not authoritative'
    return True, f'delegation verified at {parent}'
