import pathlib
import re

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
        self.assertIn('id="tag_chips"', self.page(self.admin, '/scan/p1/issues'))  # the tag chips are filled from /api/tags/


SINKS = re.compile(r'insertAdjacentHTML|document\.write|\beval\s*\(|new\s+Function|outerHTML|\.append\(\s*[\'"]<|\.prepend\(\s*[\'"]<')
LITERAL = re.compile(r"'(?:[^'\\\n]|\\.)*'|\"(?:[^\"\\\n]|\\.)*\"")
OPERAND = r"[A-Za-z_$][\w$.]*(?:\([^()]*(?:\([^()]*\)[^()]*)*\))?"
SAFE = re.compile(r'^(tag_esc\(|Number\(|encodeURIComponent\(|chips$|TAG_BULK_MAX$|S$)')


class TagScriptSinkTest(TestCase):
    """asset_tags.js builds markup by string concatenation, so every non-literal piece joined into a string must be
    escaped (tag_esc), numeric (Number) or one of the pieces built that way; text-only sinks (.text) may take raw text.
    This fails when someone concatenates a tag, title or message unescaped."""

    def source(self):
        return re.sub(r'(?m)^\s*//.*$', '', (WEB / 'static/custom/asset_tags.js').read_text())

    def test_no_dynamic_code_or_unusual_html_sinks(self):
        self.assertIsNone(SINKS.search(self.source()))

    def test_every_value_joined_into_markup_is_escaped(self):
        checked = 0
        for line in self.source().splitlines():
            stripped = LITERAL.sub('S', line)
            ops = set(re.findall(r'S\s*\+\s*(' + OPERAND + ')', stripped)) | set(re.findall('(' + OPERAND + r')\s*\+\s*S', stripped))
            for op in ops:
                checked += 1
                if '.text(' in line or '.textContent' in line:
                    continue  # text sinks: no markup is parsed
                self.assertRegex(op, SAFE, f'unescaped value joined into a string: {line.strip()}')
        self.assertGreater(checked, 8)  # the scan really saw the concatenations

    def test_tag_esc_escapes_quotes_and_angle_brackets(self):
        src = self.source()
        body = src[src.index('var TAG_ENTITIES'):src.index('function tag_chips_html')]
        for ch in ('&amp;', '&lt;', '&gt;', '&quot;', '&#39;'):
            self.assertIn(ch, body)
