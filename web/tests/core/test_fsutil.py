import os
import tempfile

from django.test import SimpleTestCase

from limes.fsutil import clear_dir, remove_results_dir, safe_rmtree


class FsutilTest(SimpleTestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.inside = os.path.join(self.root, 'scan_1')
        os.makedirs(os.path.join(self.inside, 'sub'))

    def test_removes_dir_inside_root(self):
        safe_rmtree(self.inside, roots=[self.root])
        self.assertFalse(os.path.exists(self.inside))

    def test_refuses_root_itself(self):
        with self.assertRaises(ValueError):
            safe_rmtree(self.root, roots=[self.root])

    def test_refuses_traversal_and_outside(self):
        with self.assertRaises(ValueError):
            safe_rmtree(os.path.join(self.root, '..'), roots=[self.root])
        with self.assertRaises(ValueError):
            safe_rmtree('/etc', roots=[self.root])

    def test_refuses_symlink_escape(self):
        outside = tempfile.mkdtemp()
        link = os.path.join(self.root, 'link')
        os.symlink(outside, link)
        with self.assertRaises(ValueError):
            safe_rmtree(link, roots=[self.root])
        self.assertTrue(os.path.exists(outside))

    def test_clear_dir_keeps_root(self):
        clear_dir(self.root, roots=[self.root])
        self.assertTrue(os.path.isdir(self.root))
        self.assertEqual(os.listdir(self.root), [])

    def test_remove_results_dir_skips_blank_and_disallowed(self):
        remove_results_dir('', roots=[self.root])
        remove_results_dir('/etc', roots=[self.root])
        self.assertTrue(os.path.exists('/etc'))

    def test_remove_results_dir_removes_allowed(self):
        remove_results_dir(self.inside, roots=[self.root])
        self.assertFalse(os.path.exists(self.inside))
