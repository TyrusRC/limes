from unittest import mock

from django.test import SimpleTestCase

from limes.integrations import vigil


class ExitCodeTest(SimpleTestCase):
    def test_exit_2_is_findings_not_error(self):
        self.assertTrue(vigil.is_success(2))
        self.assertTrue(vigil.is_success(0))
        self.assertFalse(vigil.is_success(1))
