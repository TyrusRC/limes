"""Delivery of a generated report: always kept in-platform; optionally a short summary by email.
The snapshot itself is never attached or sent: recipients are pointed at the Reports page."""
import logging

from django.conf import settings
from django.core.mail import EmailMessage
from django.urls import reverse

from reporting.validate import clean_text

logger = logging.getLogger(__name__)


def email_configured():
    """True when a non-SMTP backend is set (console, file, a relay package) or SMTP points at a real host."""
    if settings.EMAIL_BACKEND != 'django.core.mail.backends.smtp.EmailBackend':
        return True
    return settings.EMAIL_HOST not in ('', 'localhost', '127.0.0.1')


def subject(project, name):
    return clean_text(f'Limes report: {project.name} - {name}')


def body(project, name, d):
    sc = d['score']
    lines = [f'Report "{clean_text(name)}" for {clean_text(project.name)} is ready.', '', d['headline'], '']
    if sc['score'] is not None:
        lines.append(f"Score {sc['score']} of {sc['max']}, grade {sc['grade']}.")
    lines.append('Open the Reports page of the project in Limes to download the full report: '
                 + reverse('reports', kwargs={'slug': project.slug}))
    return '\n'.join(lines)


def deliver(run, d, schedule):
    """Send per the schedule; returns the note stored on the run. Never raises: a mail problem must not lose the report."""
    if not schedule or schedule.delivery != 'email':
        return 'In-platform only'
    to = list(schedule.recipients or [])
    if not to:
        return 'No recipients: in-platform copy only'
    if not email_configured():
        return 'Email not configured: in-platform copy only'
    sent = 0
    subj, text = subject(run.project, run.name), body(run.project, run.name, d)
    for addr in to:
        try:
            EmailMessage(subj, text, to=[addr]).send()
            sent += 1
        except Exception as exc:  # the text can carry a host and credentials: log the type only
            logger.warning('Report email failed for run %s: %s', run.pk, type(exc).__name__)
    if not sent:
        return 'Email failed: in-platform copy kept'
    if sent < len(to):
        return f'Emailed to {sent} of {len(to)} recipients'
    return f"Emailed to {sent} recipient{'s' if sent != 1 else ''}"
