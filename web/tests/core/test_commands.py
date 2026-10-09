import os
import sys
import tempfile
import time

from django.test import SimpleTestCase

from limes import commands

PY = sys.executable


class Recorder:
    def __init__(self):
        self.updates = 0
        self.result = None

    def update(self, output_tail):
        self.updates += 1

    def finish(self, result):
        self.result = result


class RunnerTest(SimpleTestCase):
    def test_rejects_strings(self):
        with self.assertRaises(commands.ShellCommandError):
            commands.run('echo hi')

    def test_rejects_non_string_items(self):
        with self.assertRaises(commands.ShellCommandError):
            commands.run(['echo', 1])

    def test_metacharacters_are_literal_arguments(self):
        result = commands.run(['echo', 'a; touch /tmp/pwned_by_test $(id)'])
        self.assertEqual(result.output.strip(), 'a; touch /tmp/pwned_by_test $(id)')
        self.assertFalse(os.path.exists('/tmp/pwned_by_test'))

    def test_timeout_kills_process_group_including_children(self):
        marker = tempfile.mktemp()
        script = (f"import subprocess,sys,time;"
                  f"subprocess.Popen([sys.executable,'-c','import time;time.sleep(3);open(\"{marker}\",\"w\")']);"
                  f"time.sleep(30)")
        start = time.monotonic()
        result = commands.run([PY, '-c', script], timeout=1)
        self.assertTrue(result.timed_out)
        self.assertIsNone(result.return_code)
        self.assertLess(time.monotonic() - start, 10)
        time.sleep(4)
        self.assertFalse(os.path.exists(marker), 'child survived the group kill')

    def test_abandoned_stream_kills_process(self):
        marker = tempfile.mktemp()
        script = f"import time;print('go', flush=True);time.sleep(2);open('{marker}','w')"
        stream = commands.stream([PY, '-c', script])
        next(stream)
        stream.close()  # what happens when SoftTimeLimitExceeded is raised while iterating
        time.sleep(3)
        self.assertFalse(os.path.exists(marker), 'process kept running after the consumer stopped')

    def test_db_writes_are_bounded(self):
        rec = Recorder()
        commands.run([PY, '-c', 'for i in range(10000): print(i)'], recorder=rec, capture=False)
        self.assertLessEqual(rec.updates, int(rec.result.duration / 5) + 2)
        self.assertEqual(rec.result.return_code, 0)
        self.assertIn('9999', rec.result.output_tail)

    def test_tail_is_bounded(self):
        result = commands.run([PY, '-c', "[print('y' * 1000) for _ in range(500)]"], capture=False)
        self.assertLessEqual(len(result.output_tail), commands.TAIL_BYTES + 1001)

    def test_output_file_written(self):
        path = tempfile.mktemp()
        commands.run(['printf', 'a\\nb\\n'], output_path=path)
        with open(path) as f:
            self.assertEqual(f.read(), 'a\nb\n')

    def test_redaction(self):
        secret = 'S3cr3tTok3n'
        rec = Recorder()
        result = commands.run(['echo', f'Authorization: {secret}'], secrets=[secret], recorder=rec)
        self.assertNotIn(secret, result.output)
        self.assertNotIn(secret, rec.result.output_tail)
        self.assertNotIn(secret, commands.display(['curl', '-H', f'X: {secret}'], [secret]))

    def test_redact_obj_scrubs_nested_report(self):
        report = {'findings': [{'request': 'GET /\r\nX-Api-Token: S3cr3t\r\n', 'n': 1}], 'k': ['S3cr3t']}
        out = commands.redact_obj(report, ['S3cr3t'])
        self.assertNotIn('S3cr3t', str(out))
        self.assertEqual(out['findings'][0]['n'], 1)

    def test_redact_tree_scrubs_all_files_on_disk(self):
        d = tempfile.mkdtemp()
        os.makedirs(os.path.join(d, 'sub'))
        paths = [os.path.join(d, 'assay-report.json'), os.path.join(d, 'sub', 'extra.txt')]
        for p in paths:
            with open(p, 'w') as f:
                f.write('{"request": "X-Api-Token: S3cr3t"}')
        commands.redact_tree(d, ['S3cr3t', ''])
        for p in paths:
            with open(p) as f:
                content = f.read()
            self.assertNotIn('S3cr3t', content)
            self.assertIn('***', content)

    def test_redact_tree_leaves_binary_files_untouched(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, 'shot.png')
        data = b'\x89PNG\xff\xfe S3cr3t \x80'
        with open(p, 'wb') as f:
            f.write(data)
        commands.redact_tree(d, ['S3cr3t'])
        with open(p, 'rb') as f:
            self.assertEqual(f.read(), data)

    def test_unopenable_output_path_does_not_leak_process(self):
        marker = tempfile.mktemp()
        script = f"import time;time.sleep(2);open('{marker}','w')"
        with self.assertRaises(OSError):
            commands.run([PY, '-c', script], output_path='/nonexistent_dir/out.txt')
        time.sleep(3)
        self.assertFalse(os.path.exists(marker), 'child leaked after open() failure')
