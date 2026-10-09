import os
import tempfile

from django.test import SimpleTestCase

from limes.urlfiles import merge_url_files


class MergeUrlFilesTest(SimpleTestCase):
    def test_merge_dedupe_sort_filter(self):
        d = tempfile.mkdtemp()
        with open(os.path.join(d, 'urls_katana.txt'), 'w') as f:
            f.write('https://a.test/b\nhttps://a.test/x.png?v=1\n\n')
        with open(os.path.join(d, 'urls_gau.txt'), 'w') as f:
            f.write('https://a.test/a\nhttps://a.test/b\n')
        inp = os.path.join(d, 'input.txt')
        with open(inp, 'w') as f:
            f.write('https://a.test/\n')
        out = os.path.join(d, 'out.txt')
        n = merge_url_files(d, inp, out, ignore_exts=['png'])
        with open(out) as f:
            self.assertEqual(f.read().splitlines(), ['https://a.test/', 'https://a.test/a', 'https://a.test/b'])
        self.assertEqual(n, 3)

    def test_missing_input_is_ignored(self):
        d = tempfile.mkdtemp()
        out = os.path.join(d, 'out.txt')
        self.assertEqual(merge_url_files(d, os.path.join(d, 'nope.txt'), out), 0)
