from django.db import connection
from django.test import SimpleTestCase, TestCase


class HarnessTest(TestCase):
    def test_database_is_postgres(self):
        self.assertEqual(connection.vendor, 'postgresql')


class ImportTest(SimpleTestCase):
    def test_tasks_module_imports(self):
        import limes.tasks  # noqa: F401
