from django.core.management.base import BaseCommand, CommandError

from dashboard.models import Project
from limes.tasks.persistence import resolve_vuln_asset
from startScan.models import Vulnerability


class Command(BaseCommand):
    help = 'Link findings saved before A4 to their inventory asset (idempotent).'

    def add_arguments(self, parser):
        parser.add_argument('project_slug', nargs='?')

    def handle(self, *args, **options):
        vulns = Vulnerability.objects.filter(asset__isnull=True).select_related('scan_history__domain', 'subdomain')
        if options['project_slug']:
            project = Project.objects.filter(slug=options['project_slug']).first()
            if not project:
                raise CommandError(f'unknown project {options["project_slug"]}')
            vulns = vulns.filter(scan_history__domain__project=project)
        linked = 0
        for v in vulns.iterator():
            asset = resolve_vuln_asset(v.scan_history, v.subdomain, v.http_url)
            if asset:
                linked += Vulnerability.objects.filter(pk=v.pk, asset__isnull=True).update(asset=asset)
        self.stdout.write(f'linked={linked}')
