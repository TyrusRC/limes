import json
import pathlib
import shutil
import subprocess

from django.contrib.auth.models import User
from django.contrib.auth.signals import user_logged_in
from django.test import TestCase
from django.utils import timezone
from rolepermissions.roles import assign_role

from dashboard.models import Project
from dashboard.views import on_user_logged_in

WEB = pathlib.Path(__file__).resolve().parents[2]


class TagsPageTest(TestCase):
    def setUp(self):
        user_logged_in.disconnect(on_user_logged_in)
        self.addCleanup(user_logged_in.connect, on_user_logged_in)
        Project.objects.create(name='p1', slug='p1', insert_date=timezone.now())
        self.admin = User.objects.create_user('adm', password='p')
        assign_role(self.admin, 'sys_admin')
        self.auditor = User.objects.create_user('aud', password='p')
        assign_role(self.auditor, 'auditor')

    def page(self, user, path):
        self.client.force_login(user)
        self.client.get(path)  # warm-up (lazy prefs creation)
        r = self.client.get(path)
        self.assertEqual(r.status_code, 200)
        return r.content.decode()

    def test_assets_page_offers_tag_controls_only_to_those_who_may_change_tags(self):
        html = self.page(self.admin, '/scan/p1/assets')
        for needle in ('id="tag_bulk_add"', 'Tag selected', 'Untag selected', 'id="asset_pick_all"', 'data-can-write="1"',
                       'custom/asset_tags.js', 'id="tag_options"', 'list="tag_options"'):
            self.assertIn(needle, html)
        html = self.page(self.auditor, '/scan/p1/assets')
        for needle in ('tag_bulk_add', 'Tag selected', 'asset_pick_all'):
            self.assertNotIn(needle, html)
        self.assertIn('data-can-write="0"', html)
        self.assertIn('id="f_tag"', html)  # reading and filtering stay open to everyone

    def test_issues_page_has_the_tag_filter(self):
        self.assertIn('id="f_tag"', self.page(self.admin, '/scan/p1/issues'))


HOSTILE = ['<img src=x onerror=alert(1)>', '"><script>alert(1)</script>', "' onmouseover='alert(1)", '&amp;']
HARNESS = """
const vm = require('vm'), fs = require('fs');
const ctx = {document: {getElementById: () => null}, fetch: () => {}, console};
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(process.argv[1], 'utf8'), ctx);
const names = JSON.parse(process.argv[2]);
console.log(JSON.stringify({chips: vm.runInContext('tag_chips_html(' + JSON.stringify(names) + ')', ctx),
                            parsed: vm.runInContext('tag_parse("a, b  c,,d")', ctx)}));
"""


class TagChipEscapingTest(TestCase):
    def test_hostile_names_never_become_markup(self):
        node = shutil.which('node')
        self.assertIsNotNone(node, 'node is required for the JS escaping test: install it in the test image')
        out = subprocess.run([node, '-e', HARNESS, str(WEB / 'static/custom/asset_tags.js'), json.dumps(HOSTILE)],
                             capture_output=True, text=True, timeout=30, check=True).stdout
        data = json.loads(out)
        chips = data['chips']
        for raw in HOSTILE[:3]:
            self.assertNotIn(raw, chips)
        for frag in ('<img', '<script', '" onmouse', "' onmouse"):
            self.assertNotIn(frag, chips)
        self.assertEqual(chips.count('<button'), len(HOSTILE))
        self.assertIn('&lt;img src=x onerror=alert(1)&gt;', chips)
        self.assertIn('&amp;amp;', chips)  # an ampersand is data, escaped once
        self.assertEqual(data['parsed'], ['a', 'b', 'c', 'd'])
