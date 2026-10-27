"""The URLs one scan run has probed, kept in the run's results dir (it replaced the EndPoint table).

One JSON line per write in `<results_dir>/endpoints.jsonl`; reading folds the lines per URL, so a
URL probed twice is one row whose fields are the latest values. A row remembers whether it was
created as a "default" URL (a host's root URL from discovery or the initial root probe), which is
what the screenshot and fetch stages start from. Stages of one run write one after another (only
readers run in parallel), so appending needs no lock.
"""
import json
import os
from urllib.parse import urlparse

from limes.definitions import ENDPOINT_SCAN_DEFAULT_DUPLICATE_FIELDS
from limes.settings import DELETE_DUPLICATES_THRESHOLD
from limes.utilities import is_valid_url

FILE = 'endpoints.jsonl'
DUPLICATE_STATUSES = (200, 301, 404)
KEEP_PATHS = ('', '/', '/login')  # never pruned: other pages redirect to them
TITLE_MAX = 1000


def is_alive(status):
	return bool(status) and 0 < status < 500 and status != 404


class RunUrls:
	"""Load once, then record/query. Create a new instance per stage call so it sees the previous stages' writes."""

	def __init__(self, results_dir):
		self.path = os.path.join(results_dir, FILE)
		self.rows = {}
		try:
			with open(self.path, errors='replace') as f:
				for line in f:
					try:
						item = json.loads(line)
					except ValueError:
						continue  # a torn last line from a killed worker
					self._apply(item)
		except FileNotFoundError:
			pass

	def _apply(self, item):
		url = item['url']
		if item.get('deleted'):
			self.rows.pop(url, None)
			return None
		row = self.rows.get(url)
		created = row is None
		if created:
			row = self.rows[url] = {'url': url, 'is_default': bool(item.get('is_default')), 'http_status': None,
									'page_title': None, 'content_length': None}
		for key in ('http_status', 'page_title', 'content_length'):
			if key in item:
				row[key] = item[key]
		if item.get('is_default') and item.get('mark'):
			row['is_default'] = True
		return created

	def _append(self, item):
		with open(self.path, 'a') as f:
			f.write(json.dumps(item) + '\n')

	def record(self, url, is_default=False, **fields):
		"""Create or update the row for url; returns True when it is new. is_default only counts at creation."""
		if 'page_title' in fields and fields['page_title'] is not None:
			fields['page_title'] = str(fields['page_title'])[:TITLE_MAX]
		item = {'url': url, **fields}
		if is_default and url not in self.rows:
			item['is_default'] = True
		created = self._apply(item)
		self._append(item)
		return created

	def mark_default(self, url):
		item = {'url': url, 'is_default': True, 'mark': True}
		if url in self.rows:
			self._apply(item)
			self._append(item)

	def forget(self, urls):
		for url in urls:
			self._apply({'url': url, 'deleted': True})
			self._append({'url': url, 'deleted': True})

	def urls(self, alive=False, default_only=False, uncrawled=False, root_host=None):
		"""Sorted, distinct, valid http(s) URLs: the same filters the EndPoint query applied."""
		out = []
		for url, row in self.rows.items():
			if default_only and not row['is_default']:
				continue
			if uncrawled and row['http_status'] is not None:
				continue
			if alive and not is_alive(row['http_status']):
				continue
			if root_host and (urlparse(url).hostname or '').lower() != root_host.lower():
				continue
			if is_valid_url(url):
				out.append(url)
		return sorted(out)

	def first_containing(self, text):
		"""The earliest-recorded URL that contains text, else None."""
		return next((u for u in self.rows if text in u), None)

	def prune_duplicates(self, only=None, fields=ENDPOINT_SCAN_DEFAULT_DUPLICATE_FIELDS):
		"""Drop the soft pages of a probe: when more than DELETE_DUPLICATES_THRESHOLD rows share one value of a
		field, keep the first and forget the rest (except root / login paths). `only` limits the rows looked at;
		empty or None looks at every row. Returns the forgotten URLs."""
		pool = [r for r in self.rows.values()
				if r['http_status'] in DUPLICATE_STATUSES and (not only or r['url'] in only)]
		removed = []
		for field in fields:
			groups = {}
			for r in pool:
				if r.get(field) is not None:
					groups.setdefault(r[field], []).append(r)
			for rows in groups.values():
				if len(rows) <= DELETE_DUPLICATES_THRESHOLD:
					continue
				for r in rows[1:]:
					if urlparse(r['url']).path in KEEP_PATHS:
						continue
					removed.append(r['url'])
					pool.remove(r)
		self.forget(removed)
		return removed
