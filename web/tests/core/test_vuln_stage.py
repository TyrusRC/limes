from unittest import mock

from django.test import SimpleTestCase

from limes.integrations import assay


class ExitCodeTest(SimpleTestCase):
    def test_exit_2_is_findings_not_error(self):
        self.assertTrue(assay.is_success(2))
        self.assertTrue(assay.is_success(0))
        self.assertFalse(assay.is_success(1))
