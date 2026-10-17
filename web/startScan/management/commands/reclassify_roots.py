from django.core.management.base import BaseCommand
from django.db import IntegrityError, transaction

from limes.intel.domains import registrable
from limes.scan_target import ensure_scan_target, has_scan_target
from startScan.models import Asset


class Command(BaseCommand):
    help = ('Turn hostname rows whose value is a registrable domain (example.co.uk) into root_domain rows, '
            'and give every owned root a scan target. Idempotent.')

    def handle(self, *args, **options):
        changed = 0
        for a in Asset.objects.filter(kind='hostname').order_by('id'):
            if registrable(a.value) != a.value:
                continue
            if Asset.objects.filter(project_id=a.project_id, kind='root_domain', value=a.value).exists():
                self.stdout.write(f'skip {a.value} (project {a.project_id}): a root_domain row already exists')
            elif a.added_by_id is None and a.parent_id is not None:
                self.stdout.write(f'skip {a.value} (project {a.project_id}): discovered under another asset, not added by a user')
            else:
                a.kind = 'root_domain'
                try:
                    with transaction.atomic():
                        a.save(update_fields=['kind'])
                except IntegrityError:
                    self.stdout.write(f'skip {a.value} (project {a.project_id}): a root_domain row appeared meanwhile')
                    continue
                changed += 1
                self.stdout.write(f'reclassified {a.value} (project {a.project_id}) as root_domain')
        linked = 0
        for a in Asset.objects.filter(kind='root_domain', scope_tier='owned_root').exclude(state='retired').order_by('id'):
            if has_scan_target(a):
                continue
            domain, warning = ensure_scan_target(a)
            if domain:
                linked += 1
                self.stdout.write(f'created scan target for {a.value} (project {a.project_id})')
            elif warning:
                self.stdout.write(f'skip scan target for {a.value} (project {a.project_id}): {warning}')
        self.stdout.write(f'reclassified={changed} linked={linked}')
