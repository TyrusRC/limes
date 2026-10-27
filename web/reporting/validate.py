"""Input rules for report schedules: the one place names and recipients are checked."""
import re

from django.core.exceptions import ValidationError
from django.core.validators import validate_email

MAX_RECIPIENTS = 20
NAME_MAX = 100
CONTROL = re.compile(r'[\x00-\x1f\x7f]')


class ReportError(ValueError):
    """The input is invalid; the message is safe to show to the user."""


def clean_text(text, limit=150):
    """Text that is safe inside a mail header or a file name: control characters become spaces."""
    return CONTROL.sub(' ', str(text)).strip()[:limit]


def name(raw):
    text = (raw or '').strip() if isinstance(raw, str) else ''
    if not text or len(text) > NAME_MAX:
        raise ReportError(f'Give the report a name of 1 to {NAME_MAX} characters.')
    if CONTROL.search(text):
        raise ReportError('The name cannot contain line breaks or control characters.')
    return text


def recipients(raw):
    """Addresses from a comma- or line-separated string (or a list): lower-cased, de-duplicated, at most MAX_RECIPIENTS."""
    items = raw if isinstance(raw, list) else re.split(r'[,\n]', raw or '')
    out = []
    for item in items:
        item = item.strip() if isinstance(item, str) else ''
        if not item:
            continue
        try:
            if len(item) > 254 or re.search(r'\s', item) or CONTROL.search(item):
                raise ValidationError('bad')
            validate_email(item)
        except ValidationError:
            raise ReportError(f'"{clean_text(item, 60)}" is not a valid email address.')
        if item.lower() not in out:
            out.append(item.lower())
    if len(out) > MAX_RECIPIENTS:
        raise ReportError(f'At most {MAX_RECIPIENTS} recipients.')
    return out
