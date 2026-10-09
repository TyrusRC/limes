import random
from datetime import timedelta

from django.core.management.base import BaseCommand
from django.utils import timezone

from dashboard.models import Project
from scanEngine.models import EngineType
from startScan.models import EndPoint, ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain

BATCH = 5000


class Command(BaseCommand):
    help = 'Bulk-seed a "bench" project for dashboard benchmarks (lab data only).'

    def add_arguments(self, parser):
        parser.add_argument('--domains', type=int, default=50)
        parser.add_argument('--subs', type=int, default=4000)
        parser.add_argument('--endpoints', type=int, default=20000)
        parser.add_argument('--vulns', type=int, default=1000)

    def handle(self, *args, **opts):
        now = timezone.now()
        project, _ = Project.objects.get_or_create(slug='bench', defaults={'name': 'bench', 'insert_date': now})
        engine, _ = EngineType.objects.get_or_create(engine_name='bench-seed', defaults={'yaml_configuration': 'http_crawl: {}'})
        rnd = random.Random(42)
        for d in range(opts['domains']):
            domain, _ = Domain.objects.get_or_create(
                name=f'seed{d}.bench.test', defaults={'project': project, 'insert_date': now})
            scan = ScanHistory.objects.create(
                domain=domain, scan_type=engine, start_scan_date=now, scan_status=2)
            subs = [Subdomain(name=f's{i}.{domain.name}', scan_history=scan, target_domain=domain,
                              http_status=rnd.choice([0, 200, 301, 403, 404]),
                              discovered_date=now - timedelta(days=rnd.randint(0, 13)))
                    for i in range(opts['subs'])]
            Subdomain.objects.bulk_create(subs, batch_size=BATCH)
            sub_ids = list(Subdomain.objects.filter(scan_history=scan).values_list('id', flat=True))
            eps = [EndPoint(http_url=f'https://s{i % opts["subs"]}.{domain.name}/p{i}', scan_history=scan,
                            target_domain=domain, subdomain_id=sub_ids[i % len(sub_ids)],
                            http_status=rnd.choice([200, 302, 404, 500]),
                            discovered_date=now - timedelta(days=rnd.randint(0, 13)))
                   for i in range(opts['endpoints'])]
            EndPoint.objects.bulk_create(eps, batch_size=BATCH)
            vulns = [Vulnerability(name=f'bench-vuln-{i % 40}', severity=rnd.choice([-1, 0, 1, 2, 3, 4]),
                                   scan_history=scan, target_domain=domain,
                                   subdomain_id=sub_ids[i % len(sub_ids)],
                                   discovered_date=now - timedelta(days=rnd.randint(0, 13)))
                     for i in range(opts['vulns'])]
            Vulnerability.objects.bulk_create(vulns, batch_size=BATCH)
            self.stdout.write(f'seeded {domain.name}')
