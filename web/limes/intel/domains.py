"""Registrable-domain decisions from the bundled public-suffix snapshot (never fetched)."""
import tldextract

_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())


def registrable(name):
    n = (name or '').strip().rstrip('.').lower()
    if not n:
        return None
    try:
        n = n.encode('idna').decode('ascii')
    except UnicodeError:
        return None
    return _EXTRACT(n).registered_domain or None
