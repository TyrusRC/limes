from django.test import SimpleTestCase

from limes.ct import match

I = match.Index


def idx(roots=None, hosts=None, lookalikes=None):
    return I(roots or {}, hosts or {}, lookalikes or {})


class NormaliseTest(SimpleTestCase):
    def test_normalise(self):
        self.assertEqual(match.normalise('*.X.com.'), ('x.com', True))
        self.assertEqual(match.normalise(' Www.X.com '), ('www.x.com', False))
        n, w = match.normalise('bücher.example')
        self.assertEqual((n, w), ('xn--bcher-kva.example', False))
        for bad in ['', 'a..b', '-a.com', 'a b.com', 'a\nb.x.com', '<img src=x>.x.com', 'x' * 254, '1.2.3.4',
                    'a\x00.x.com', 'x.com\x00.evil.net', '*.*.x.com', 'a.*.x.com', 'x.com/..', 'x.com@evil.net',
                    'evil。x.com', 'evil．x.com', 'x.com..', None, 5, b'x.com', 'a' * 64 + '.x.com']:
            self.assertIsNone(match.normalise(bad), repr(bad))


    def test_lookalike_unicode_is_not_folded_onto_ascii(self):
        for bad in ['\uff57\uff57\uff57.x.com',  # full-width www
                    '\u24e7.com',                 # circled x
                    'x\u200b.com',                # zero-width space
                    'x\u00ad.com',                # soft hyphen
                    '\ufb01.x.com',               # fi ligature
                    '\u212a.x.com',               # Kelvin sign (lowercases to ASCII k)
                    'xn--zzzz\u00e9.com',
                    'xn--.x.com']:
            self.assertIsNone(match.normalise(bad), repr(bad))
        self.assertNotEqual(match.normalise('stra\u00dfe.x.com'), ('strasse.x.com', False))  # IDNA 2008 keeps sharp s apart
        m, _ = match.classify(['\u212aelvin.x.com', 'www.x.com'], idx(roots={'x.com': [(1, 10)]}))
        self.assertEqual(m[1].owned, [('www.x.com', False, 10)])


class ClassifyTest(SimpleTestCase):
    def test_longest_root_wins(self):
        i = idx(roots={'x.com': [(1, 10)], 'a.x.com': [(1, 11)]})
        m, _ = match.classify(['b.a.x.com', 'c.x.com'], i)
        self.assertEqual(m[1].owned, [('b.a.x.com', False, 11), ('c.x.com', False, 10)])

    def test_name_equal_to_root_and_wildcard(self):
        m, _ = match.classify(['x.com', '*.x.com'], idx(roots={'x.com': [(1, 10)]}))
        self.assertEqual(m[1].owned, [('x.com', False, 10), ('x.com', True, 10)])

    def test_host_and_lookalike_and_other(self):
        i = idx(hosts={'app.vendor.com': [(1, 5)]}, lookalikes={'examp1e.com': [1]})
        m, dropped = match.classify(['app.vendor.com', 'login.examp1e.com', 'z.org', 'bad name'], i)
        self.assertEqual(m[1].hosts, [('app.vendor.com', 5)])
        self.assertEqual(m[1].lookalikes, ['examp1e.com'])
        self.assertEqual(m[1].others, ['z.org'])
        self.assertEqual((m[1].owned, dropped), ([], 1))

    def test_project_with_only_others_is_absent(self):
        m, _ = match.classify(['z.org'], idx(roots={'x.com': [(1, 10)]}))
        self.assertEqual(m, {})

    def test_projects_classified_separately(self):
        i = idx(roots={'x.com': [(1, 10), (2, 20)]}, hosts={'a.y.com': [(2, 21)]})
        m, _ = match.classify(['www.x.com', 'a.y.com'], i)
        self.assertEqual(m[1].owned, [('www.x.com', False, 10)])
        self.assertEqual(m[1].others, ['a.y.com'])
        self.assertEqual(m[2].owned, [('www.x.com', False, 20)])
        self.assertEqual(m[2].hosts, [('a.y.com', 21)])

    def test_truncation_counted(self):
        names = [f'h{i}.x.com' for i in range(1005)]
        m, dropped = match.classify(names, idx(roots={'x.com': [(1, 10)]}))
        self.assertGreaterEqual(dropped, 5)
        self.assertEqual(len(m[1].owned), 1000)

    def test_hostile_names_rejected(self):
        i = idx(roots={'x.com': [(1, 10)]})
        hostile = ['x.com\x00.evil.net', 'x.com.\x00', '<x>.x.com', 'a b.x.com', 'x.com/evil.net', 'x.com@evil.net',
                   'evil。x.com', 'x.com\n.evil', '*.*.x.com']
        m, dropped = match.classify(hostile, i)
        self.assertEqual((m, dropped), ({}, len(hostile)))

    def test_suffix_tricks_never_own(self):
        i = idx(roots={'x.com': [(1, 10)]})
        m, _ = match.classify(['www.x.com', 'evilx.com', 'x.com.evil.net', 'xx.com', 'x.com-evil.net'], i)
        self.assertEqual(m[1].owned, [('www.x.com', False, 10)])
        self.assertEqual(m[1].others, ['evilx.com', 'x.com.evil.net', 'xx.com', 'x.com-evil.net'])

    def test_punycode_name_matches_unicode_input(self):
        m, _ = match.classify(['www.bücher.example'], idx(roots={'xn--bcher-kva.example': [(1, 10)]}))
        self.assertEqual(m[1].owned, [('www.xn--bcher-kva.example', False, 10)])

    def test_duplicate_names_collapse(self):
        m, _ = match.classify(['A.x.com', 'a.x.com.'], idx(roots={'x.com': [(1, 10)]}))
        self.assertEqual(m[1].owned, [('a.x.com', False, 10)])


class IssuerOrgTest(SimpleTestCase):
    def test_issuer_org(self):
        self.assertEqual(match.issuer_org("C=US, O=Let's Encrypt, CN=R11"), "Let's Encrypt")
        self.assertEqual(match.issuer_org('CN=Foo CA,O=Acme\\, Inc.,C=US'), 'Acme, Inc.')
        self.assertEqual(match.issuer_org('/C=US/O=DigiCert Inc/CN=x'), 'DigiCert Inc')
        self.assertEqual(match.issuer_org('CN=Only'), 'Only')
        self.assertEqual(match.issuer_org(''), '')
        self.assertEqual(len(match.issuer_org('O=' + 'A' * 1000)), 200)
        self.assertEqual(match.issuer_org('O=Evil\n\x00  CA'), 'Evil CA')
        self.assertEqual(match.issuer_org(None), '')
