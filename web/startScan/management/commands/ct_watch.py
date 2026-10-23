import sys

from django.core.management.base import BaseCommand

from limes.ct import watch


class Command(BaseCommand):
    help = 'Run the certificate watcher (certspotter supervisor); --health exits 0 when its heartbeat is fresh.'

    def add_arguments(self, parser):
        parser.add_argument('--health', action='store_true')

    def handle(self, *args, **opts):
        if opts['health']:
            sys.exit(watch.health_exit_code())
        watch.run()
