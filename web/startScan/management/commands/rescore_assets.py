from django.core.management.base import BaseCommand, CommandError

from dashboard.models import Project
from limes.tasks import attribution


class Command(BaseCommand):
    help = ('Re-score candidate ownership with the current attribution weights '
            '(--decide also verifies delegations at the registry and applies decisions).')

    def add_arguments(self, parser):
        parser.add_argument('project_slug')
        parser.add_argument('--decide', action='store_true',
                            help='also query the registry for delegations (network) and apply auto-confirm decisions')

    def handle(self, *args, **options):
        project = Project.objects.filter(slug=options['project_slug']).first()
        if not project:
            raise CommandError(f'unknown project {options["project_slug"]}')
        counts = attribution.score_project(project)
        if options['decide']:
            counts = {**counts, **attribution.verify_delegations(project), **attribution.apply_decisions(project)}
        self.stdout.write(', '.join(f'{k}={v}' for k, v in counts.items()))
