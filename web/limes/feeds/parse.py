"""Strict parsers for hostile feed bytes. Nothing is executed or eval'd; every record is validated, bad ones are
counted in meta['dropped'] and skipped. Each parser returns (data, meta) with meta['rows'] = valid entries."""
import gzip
import io
import ipaddress
import json
import math
import re
from datetime import date, datetime, timezone
from urllib.parse import urlsplit

MAX_BYTES = 50 * 1024 * 1024  # decompressed bytes a parser will read
CHUNK = 64 * 1024
MAX_LINE = 4096  # NDJSON / CSV rows are short; a longer line is junk
MAX_ROWS = 2_000_000  # NOTE: ~5x today's EPSS (394k rows); more is treated as a broken or hostile feed
MAX_JSON = 20 * 1024 * 1024
MAX_JSON_ROWS = 200_000

CVE_RE = re.compile(r'^CVE-\d{4}-\d{4,7}$')
SBL_RE = re.compile(r'^SBL\d{1,10}$')
TLD_RE = re.compile(r'^[a-z0-9-]{1,63}$')
_PRINTABLE = re.compile(r'[^\x20-\x7e]')


class ParseError(ValueError):
    pass


def norm_cve(value):
    if not isinstance(value, str) or len(value) > 64:
        return None
    value = value.strip().upper()
    return value if CVE_RE.match(value) else None


def _clean(value, limit):
    return _PRINTABLE.sub('', value)[:limit] if isinstance(value, str) else ''


def _meta(rows, dropped, **extra):
    return {'rows': rows, 'dropped': dropped, **extra}


def _lines(blob):
    for raw in blob.split(b'\n'):
        raw = raw.strip()
        if raw:
            yield raw


def _json(blob, limit=MAX_JSON):
    if len(blob) > limit:
        raise ParseError('json too large')
    return json.loads(blob)


def _ts(value):
    """A feed timestamp (unix seconds or ISO 8601) as an aware datetime, or None."""
    try:
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return datetime.fromtimestamp(value, timezone.utc)
        dt = datetime.fromisoformat(str(value).strip().replace('Z', '+00:00'))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except (ValueError, OverflowError, OSError):
        return None


def _date(value):
    try:
        return date.fromisoformat(value) if isinstance(value, str) else None
    except ValueError:
        return None


def _public(net_or_ip):
    """Reserved, private, loopback, link-local... ranges never belong in a threat feed; drop them."""
    if isinstance(net_or_ip, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
        return net_or_ip.network_address.is_global and net_or_ip.broadcast_address.is_global
    return net_or_ip.is_global


def spamhaus_drop(blob):
    out, dropped, meta = [], 0, {}
    for raw in _lines(blob):
        if len(raw) > MAX_LINE:
            dropped += 1
            continue
        try:
            rec = json.loads(raw)
        except ValueError:
            dropped += 1
            continue
        if not isinstance(rec, dict):
            dropped += 1
        elif rec.get('type') == 'metadata':
            meta = {'source_date': _ts(rec.get('timestamp')), 'copyright': _clean(rec.get('copyright'), 200)}
        else:
            cidr, sbl = rec.get('cidr'), rec.get('sblid')
            try:
                net = ipaddress.ip_network(cidr, strict=True) if isinstance(cidr, str) else None
            except ValueError:
                net = None
            # NOTE: a whole-internet entry would list every owned IP; real DROP entries are far narrower
            if (net is None or not isinstance(sbl, str) or not SBL_RE.match(sbl) or not _public(net)
                    or net.prefixlen < (8 if net.version == 4 else 16)):
                dropped += 1
            else:
                out.append((str(net), sbl))
        if len(out) > MAX_JSON_ROWS:
            raise ParseError('too many rows')
    return out, _meta(len(out), dropped, source_date=meta.get('source_date'), copyright=meta.get('copyright', ''))


def spamhaus_asndrop(blob):
    out, dropped, source_date = [], 0, None
    for raw in _lines(blob):
        try:
            rec = json.loads(raw) if len(raw) <= MAX_LINE else None
        except ValueError:
            rec = None
        if not isinstance(rec, dict):
            dropped += 1
        elif rec.get('type') == 'metadata':
            source_date = _ts(rec.get('timestamp'))
        else:
            asn = rec.get('asn')
            if isinstance(asn, int) and not isinstance(asn, bool) and 1 <= asn < 2 ** 32:
                out.append((asn, _clean(rec.get('asname'), 100)))
            else:
                dropped += 1
        if len(out) > MAX_JSON_ROWS:
            raise ParseError('too many rows')
    return out, _meta(len(out), dropped, source_date=source_date)


def feodo(blob):
    data = _json(blob)
    if not isinstance(data, list) or len(data) > MAX_JSON_ROWS:
        raise ParseError('unexpected shape')
    out, dropped = [], 0
    for rec in data:
        try:
            ip = ipaddress.ip_address(rec['ip_address']) if isinstance(rec, dict) else None
        except (KeyError, ValueError):
            ip = None
        if ip is None or not _public(ip):
            dropped += 1
        elif str(ip) not in out:
            out.append(str(ip))
    return out, _meta(len(out), dropped)


def plain_ips(blob):
    seen, dropped = set(), 0
    for raw in _lines(blob):
        if raw.startswith(b'#'):
            continue
        try:
            ip = ipaddress.ip_address(raw.decode('ascii')) if len(raw) <= 64 else None
        except ValueError:  # includes UnicodeDecodeError
            ip = None
        if ip is None or not _public(ip):
            dropped += 1
        else:
            seen.add(str(ip))
        if len(seen) > MAX_ROWS:
            raise ParseError('too many rows')
    return sorted(seen), _meta(len(seen), dropped)


def kev(blob):
    data = _json(blob)
    vulns = data.get('vulnerabilities') if isinstance(data, dict) else None
    if not isinstance(vulns, list) or len(vulns) > MAX_JSON_ROWS:
        raise ParseError('unexpected shape')
    out, dropped = {}, 0
    for rec in vulns:
        cve = norm_cve(rec.get('cveID')) if isinstance(rec, dict) else None
        if cve is None:
            dropped += 1
            continue
        out[cve] = {'added': _date(rec.get('dateAdded')), 'due': _date(rec.get('dueDate')),
                    'ransomware': rec.get('knownRansomwareCampaignUse') == 'Known'}
    return out, _meta(len(out), dropped, source_date=_ts(data.get('dateReleased')))


def _gunzip_lines(blob):
    """Lines of a gzip stream, read in chunks; aborts as soon as MAX_BYTES decompressed bytes are exceeded."""
    total, rest = 0, b''
    with gzip.GzipFile(fileobj=io.BytesIO(blob)) as gz:
        while True:
            try:
                chunk = gz.read(CHUNK)
            except (OSError, EOFError) as e:
                raise ParseError(type(e).__name__) from None
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_BYTES:
                raise ParseError('inflates past the size cap')
            parts = (rest + chunk).split(b'\n')
            rest = parts.pop()
            if len(rest) > MAX_LINE:
                raise ParseError('line too long')
            yield from parts
    if rest:
        yield rest


_EPSS_HEAD = re.compile(r'model_version:\s*([\w.\-]{1,32}).*?score_date:\s*([\w:.+\-]{1,40})')


def epss(blob, wanted=None):
    """`rows` counts every valid row; `data` holds only `wanted` ids (nothing when `wanted` is None).
    Values outside [0, 1] (or not finite) are dropped."""
    wanted = wanted or set()
    out, rows, dropped, version, source_date = {}, 0, 0, '', None
    for raw in _gunzip_lines(blob):
        line = raw.strip()
        if not line:
            continue
        if line.startswith(b'#'):
            m = _EPSS_HEAD.search(line.decode('ascii', 'replace'))
            if m:
                version, source_date = m.group(1), _ts(m.group(2))
            continue
        if line.startswith(b'cve,'):
            continue
        parts = line.decode('ascii', 'replace').split(',')
        cve = norm_cve(parts[0]) if len(parts) == 3 else None
        try:
            score, pct = float(parts[1]), float(parts[2])
        except (IndexError, ValueError):
            cve = None
        if cve is None or not (math.isfinite(score) and math.isfinite(pct) and 0 <= score <= 1 and 0 <= pct <= 1):
            dropped += 1
            continue
        rows += 1
        if rows > MAX_ROWS:
            raise ParseError('too many rows')
        if cve in wanted:
            out[cve] = (score, pct)
    return out, _meta(rows, dropped, source_date=source_date, model_version=version)


def rdap_bootstrap(blob):
    data = _json(blob, 5 * 1024 * 1024)
    services = data.get('services') if isinstance(data, dict) else None
    if not isinstance(services, list) or len(services) > 5000:
        raise ParseError('unexpected shape')
    out, dropped = {}, 0
    for svc in services:
        if not (isinstance(svc, list) and len(svc) == 2 and all(isinstance(x, list) for x in svc)):
            dropped += 1
            continue
        base = next((u for u in (_https_base(u) for u in svc[1][:20]) if u), None)
        for tld in svc[0][:5000]:
            tld = tld.lower() if isinstance(tld, str) else ''
            if base and TLD_RE.match(tld):
                out[tld] = base
            else:
                dropped += 1
    return out, _meta(len(out), dropped, source_date=_ts(data.get('publication')))


def _https_base(url):
    if not isinstance(url, str) or len(url) > 200 or _PRINTABLE.search(url):
        return None
    try:
        u = urlsplit(url)
        port = u.port
    except ValueError:
        return None
    if u.scheme != 'https' or not u.hostname or u.username or u.password or port not in (None, 443):
        return None
    return url if url.endswith('/') else url + '/'


PARSERS = {'spamhaus_drop': spamhaus_drop, 'spamhaus_asndrop': spamhaus_asndrop, 'feodo': feodo,
           'plain_ips': plain_ips, 'kev': kev, 'epss': epss, 'rdap_bootstrap': rdap_bootstrap}
