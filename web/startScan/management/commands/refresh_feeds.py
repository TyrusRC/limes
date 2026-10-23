from django.core.management.base import BaseCommand, CommandError

from limes.feeds import sources, tasks


class Command(BaseCommand):
    help = ('Fetch one reputation feed now. The daily download budget and the feed tick lock still apply. '
            '--force accepts a copy that the shrink or record-count checks would refuse (an operator '
            'override); it never bypasses the size cap, redirect rules or garbage/empty-page rejection.')

    def add_arguments(self, parser):
        parser.add_argument('name', choices=sorted(sources.FEEDS))
        parser.add_argument('--force', action='store_true', help='skip the shrink and record-count checks')

    def handle(self, *args, name, force=False, **options):
        status = tasks.refresh_one(name, force=force)
        self.stdout.write(f'{name}: {status}')
        if status in ('locked', 'budget', 'error', 'rejected'):
            raise CommandError(f'{name}: {status}')
