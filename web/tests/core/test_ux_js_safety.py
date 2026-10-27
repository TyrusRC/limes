import os
import re

from django.test import SimpleTestCase

STATIC = os.path.join(os.path.dirname(__file__), '..', '..', 'static', 'limes')
NEW_JS = ['ux.js', 'risk.js', 'issues.js', 'assets_ux.js', 'home.js', 'overview.js',
          'remediation_new.js', 'remediation_detail.js', 'waivers.js']  # extend when a new UI script lands: these build DOM with textContent only
BAD = ('innerHTML', 'outerHTML', 'insertAdjacentHTML', '.html(', 'document.write', 'eval(', 'new Function', 'srcdoc')


class UxScriptsBuildNoHtmlTest(SimpleTestCase):
    def test_no_html_sinks(self):
        for name in NEW_JS:
            with open(os.path.join(STATIC, name)) as f:
                js = f.read()
            for bad in BAD:
                self.assertNotIn(bad, js, f'{name} uses {bad}')

    def test_no_href_assignment_from_data(self):
        for name in NEW_JS:
            with open(os.path.join(STATIC, name)) as f:
                js = f.read()
            # a link target is only ever built from a number by detailUrl()
            for line in js.splitlines():
                if re.search(r"\.href\s*=|setAttribute\(\s*'href'", line):
                    self.assertIn('detailUrl(', line, f'{name} sets a link from data: {line.strip()}')
