"""The third-party feeds Limes downloads: one place for URL, cadence, parser, licence and credit text."""
from collections import namedtuple
from datetime import timedelta

from django.conf import settings

# `parser` names an entry of limes.feeds.parse.PARSERS; `terms` is the publisher's terms/licence page (https).
Feed = namedtuple('Feed', 'name url cadence parser credit terms optin allow_empty licence')

H, D = timedelta(hours=1), timedelta(days=1)
_SPAMHAUS = 'https://www.spamhaus.org/blocklists/do-not-route-or-peer/'
_SPAMHAUS_CREDIT = 'Contains data from The Spamhaus Project'
_SPAMHAUS_LICENCE = 'Free for any organisation; credit to The Spamhaus Project, date and copy text kept with the file'
_ABUSE = 'https://abuse.ch/terms-of-use/'

FEEDS = {f.name: f for f in (
    Feed('drop_v4', 'https://www.spamhaus.org/drop/drop_v4.json', D, 'spamhaus_drop', _SPAMHAUS_CREDIT, _SPAMHAUS,
         False, False, _SPAMHAUS_LICENCE),
    Feed('drop_v6', 'https://www.spamhaus.org/drop/drop_v6.json', D, 'spamhaus_drop', _SPAMHAUS_CREDIT, _SPAMHAUS,
         False, False, _SPAMHAUS_LICENCE),
    Feed('asndrop', 'https://www.spamhaus.org/drop/asndrop.json', D, 'spamhaus_asndrop', _SPAMHAUS_CREDIT, _SPAMHAUS,
         False, False, _SPAMHAUS_LICENCE),
    # NOTE: Feodo may legitimately list nothing (allow_empty); SSLBL was deprecated on 2025-01-03 and is not used.
    Feed('feodo', 'https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json', 6 * H, 'feodo',
         'abuse.ch Feodo Tracker (CC0)', _ABUSE, False, True, 'CC0 1.0'),
    Feed('kev', 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', D, 'kev',
         'CISA KEV (CC0)', 'https://www.cisa.gov/sites/default/files/licenses/kev/license.txt', False, False, 'CC0 1.0'),
    Feed('epss', 'https://epss.empiricalsecurity.com/epss_scores-current.csv.gz', D, 'epss',
         'EPSS by FIRST.org / Empirical Security', 'https://www.first.org/epss/faq', False, False,
         'Free; attribution requested; never redistributed'),
    Feed('iana_rdap', 'https://data.iana.org/rdap/dns.json', 7 * D, 'rdap_bootstrap',
         'RDAP bootstrap data from IANA', 'https://www.iana.org/help/licensing-terms', False, False,
         'CC0 1.0 dedication (IANA registries are "subject to the Creative Commons CC0 1.0 dedication"); no attribution requested'),
    # Off by default (LIMES_FEEDS_OPTIN): terms unclear.
    Feed('blocklist_de', 'https://lists.blocklist.de/lists/all.txt', D, 'plain_ips', 'Data from blocklist.de',
         'https://www.blocklist.de/en/terms.html', True, True, 'No licence stated; use at your own risk'),
    Feed('cins', 'https://cinsscore.com/list/ci-badguys.txt', D, 'plain_ips', 'Data from CINS Army (cinsscore.com)',
         'https://cinsscore.com/', True, True, '"parse and use in any way you see fit"; redistribution not addressed'),
)}

REPUTATION = ('drop_v4', 'drop_v6', 'asndrop', 'feodo', 'blocklist_de', 'cins')


def enabled(feed):
    return not feed.optin or feed.name in settings.FEEDS_OPTIN
