from django.contrib.auth.models import User
from django.db import models
from django.utils import timezone

from dashboard.models import Project

FREQUENCIES = (('weekly', 'Weekly'), ('monthly', 'Monthly'), ('quarterly', 'Quarterly'))
WEEKDAYS = ((0, 'Monday'), (1, 'Tuesday'), (2, 'Wednesday'), (3, 'Thursday'), (4, 'Friday'), (5, 'Saturday'), (6, 'Sunday'))
DELIVERIES = (('platform', 'In-platform only'), ('email', 'In-platform and email'))


LAYOUTS = (('full', 'Full report'), ('board', 'Board summary (one page)'))
SECTIONS = (('score', 'Score and history'), ('categories', 'Category breakdown'), ('risks', 'Top risks'),
            ('changes', 'New and resolved changes'), ('waivers', 'Waivers'), ('remediation', 'Remediation status'),
            ('assets', 'Tags and assets summary'))
COMMENTARY_MAX = 2000


class ReportTemplate(models.Model):
    """A saved report layout for one project: which sections, plus plain-text commentary (escaped wherever shown).
    The board layout ignores sections and uses the commentary as 'what we need decided'."""
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='report_templates')
    name = models.CharField(max_length=100)
    layout = models.CharField(max_length=10, choices=LAYOUTS, default='full')
    sections = models.JSONField(default=list, blank=True)
    commentary = models.TextField(blank=True, default='', max_length=COMMENTARY_MAX)
    created_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name='+')
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        constraints = [models.UniqueConstraint(fields=['project', 'name'], name='report_template_name_once')]
        ordering = ['name', 'id']


class ReportSchedule(models.Model):
    """A recurring executive-summary report. Day and hour are UTC; weekday applies to weekly, day_of_month (1-28, so
    every month has it) to monthly and quarterly. The report covers WINDOW_DAYS of history."""
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='report_schedules')
    name = models.CharField(max_length=100)
    frequency = models.CharField(max_length=10, choices=FREQUENCIES, default='monthly')
    weekday = models.PositiveSmallIntegerField(default=0)  # 0 = Monday
    day_of_month = models.PositiveSmallIntegerField(default=1)
    hour = models.PositiveSmallIntegerField(default=6)
    tag = models.CharField(max_length=100, blank=True, default='')
    template = models.ForeignKey(ReportTemplate, null=True, blank=True, on_delete=models.SET_NULL, related_name='schedules')
    recipients = models.JSONField(default=list, blank=True)
    delivery = models.CharField(max_length=10, choices=DELIVERIES, default='platform')
    enabled = models.BooleanField(default=True)
    created_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name='+')
    created_at = models.DateTimeField(default=timezone.now)

    WINDOW_DAYS = {'weekly': 30, 'monthly': 30, 'quarterly': 90}

    @property
    def window_days(self):
        return self.WINDOW_DAYS[self.frequency]

    @property
    def when(self):
        at = f'{self.hour:02d}:00'
        if self.frequency == 'weekly':
            return f'{WEEKDAYS[self.weekday % 7][1]} {at}'
        return f"day {self.day_of_month}{' of the quarter' if self.frequency == 'quarterly' else ''} {at}"


class ReportRun(models.Model):
    """One generated report: a private HTML snapshot under the results dir (file is a bare name, never a path).
    A scheduled run is unique per (schedule, period_key), which is what makes the beat task idempotent."""
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='report_runs')
    schedule = models.ForeignKey(ReportSchedule, null=True, blank=True, on_delete=models.SET_NULL, related_name='runs')
    name = models.CharField(max_length=100)
    trigger = models.CharField(max_length=10, default='manual')  # schedule | manual
    period_key = models.CharField(max_length=40, blank=True, default='')
    tag = models.CharField(max_length=100, blank=True, default='')
    days = models.PositiveSmallIntegerField(default=90)
    generated_at = models.DateTimeField(default=timezone.now)
    file = models.CharField(max_length=80)
    size = models.PositiveIntegerField(default=0)
    delivery_note = models.CharField(max_length=200, blank=True, default='')
    created_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name='+')

    class Meta:
        constraints = [models.UniqueConstraint(fields=['schedule', 'period_key'], name='report_run_once_per_period')]
        ordering = ['-generated_at', '-id']
