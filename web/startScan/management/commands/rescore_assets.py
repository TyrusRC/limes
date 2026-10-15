from django.core.management.base import BaseCommand, CommandError

from dashboard.models import Project
from limes.tasks import attribution


class Command(BaseCommand):
    help = 'Re-score candidate ownership with the current attribution weights (--decide also applies decisions).'

    def add_arguments(self, parser):
        parser.add_argument('project_slug')
        parser.add_argument('--decide', action='store_true',
                            help='also apply auto-confirm decisions (needs fresh NS facts)')

    def handle(self, *args, **options):
        project = Project.objects.filter(slug=options['project_slug']).first()
        if not project:
            raise CommandError(f'unknown project {options["project_slug"]}')
        counts = attribution.score_project(project)
        if options['decide']:
            counts = {**counts, **attribution.apply_decisions(project)}
        self.stdout.write(', '.join(f'{k}={v}' for k, v in counts.items()))
