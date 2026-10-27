import tempfile

from django.test import SimpleTestCase

from limes.run_urls import RunUrls, is_alive


class RunUrlsTest(SimpleTestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.store = RunUrls(self.dir)

    def test_a_new_instance_sees_what_an_earlier_one_wrote(self):
        self.store.record('https://a.x.com', is_default=True, http_status=200)
        self.assertEqual(RunUrls(self.dir).urls(alive=True, default_only=True), ['https://a.x.com'])

    def test_the_same_url_is_one_row_with_the_latest_fields_and_the_first_default_flag(self):
        self.assertTrue(self.store.record('https://a.x.com/p', http_status=200, page_title='one'))
        self.assertFalse(self.store.record('https://a.x.com/p', is_default=True, http_status=503))
        row = RunUrls(self.dir).rows['https://a.x.com/p']
        self.assertEqual((row['http_status'], row['page_title'], row['is_default']), (503, 'one', False))
        self.store.mark_default('https://a.x.com/p')
        self.assertTrue(RunUrls(self.dir).rows['https://a.x.com/p']['is_default'])

    def test_alive_means_a_status_under_500_that_is_not_404(self):
        self.assertEqual([is_alive(s) for s in (None, 0, 200, 301, 403, 404, 499, 500)],
                         [False, False, True, True, True, False, True, False])

    def test_filters(self):
        for url, status, default in (('https://a.x.com', 200, True), ('https://a.x.com/up', 200, False),
                                     ('https://a.x.com/gone', 404, False), ('https://b.x.com:8443', 0, True),
                                     ('https://never.x.com', None, False), ('ftp://a.x.com/file', 200, False)):
            self.store.record(url, is_default=default, http_status=status)
        self.assertEqual(self.store.urls(alive=True), ['https://a.x.com', 'https://a.x.com/up'])
        self.assertEqual(self.store.urls(default_only=True), ['https://a.x.com', 'https://b.x.com:8443'])
        self.assertEqual(self.store.urls(uncrawled=True), ['https://never.x.com'])
        self.assertEqual(self.store.urls(alive=True, root_host='A.x.com'), ['https://a.x.com', 'https://a.x.com/up'])
        self.assertEqual(self.store.urls(root_host='x.com'), [])
        self.assertEqual(len(self.store.urls()), 5)  # the ftp URL is not a valid http(s) URL

    def test_first_containing_is_the_earliest_recorded(self):
        for url in ('https://z.x.com:22', 'https://a.x.com:22'):
            self.store.record(url)
        self.assertEqual(RunUrls(self.dir).first_containing(':22'), 'https://z.x.com:22')
        self.assertIsNone(self.store.first_containing('nowhere'))

    def test_a_torn_last_line_from_a_killed_worker_is_skipped(self):
        self.store.record('https://a.x.com', http_status=200)
        with open(self.store.path, 'a') as f:
            f.write('{"url": "https://b.x')
        self.assertEqual(RunUrls(self.dir).urls(), ['https://a.x.com'])


class PruneDuplicatesTest(SimpleTestCase):
    def setUp(self):
        self.store = RunUrls(tempfile.mkdtemp())

    def page(self, path, length=777, status=200, title=None):
        self.store.record(f'https://a.x.com{path}', http_status=status, content_length=length, page_title=title)

    def test_more_than_the_threshold_of_one_length_keeps_the_first_and_the_root_and_login_pages(self):
        self.page('/first')
        self.page('/login')
        self.page('/')
        for i in range(10):
            self.page(f'/p{i}')
        removed = self.store.prune_duplicates()
        self.assertEqual(removed, [f'https://a.x.com/p{i}' for i in range(10)])
        self.assertEqual(sorted(RunUrls(self.store.path.rsplit('/', 1)[0]).urls()),
                         ['https://a.x.com/', 'https://a.x.com/first', 'https://a.x.com/login'])

    def test_exactly_the_threshold_is_left_alone(self):
        for i in range(10):
            self.page(f'/p{i}')
        self.assertEqual(self.store.prune_duplicates(), [])

    def test_only_200_301_and_404_are_looked_at_and_an_unset_value_never_groups(self):
        for i in range(12):
            self.page(f'/e{i}', status=500)
            self.page(f'/n{i}', length=None)
        self.assertEqual(self.store.prune_duplicates(), [])

    def test_titles_group_too_and_only_limits_the_rows_looked_at(self):
        for i in range(12):
            self.page(f'/t{i}', length=i, title='Not found')
        self.assertEqual(self.store.prune_duplicates(only={'https://a.x.com/t3'}), [])  # one row cannot exceed it
        self.assertEqual(len(self.store.prune_duplicates()), 11)
