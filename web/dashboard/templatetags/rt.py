from django import template

register = template.Library()


@register.filter
def rt_age(seconds):
    """Mirrors fmtAge() in overview.js: 45s, 12m, 3h, 2d; None is a dash."""
    if not isinstance(seconds, int) or isinstance(seconds, bool):
        return '—'
    if seconds < 60:
        return f'{seconds}s'
    if seconds < 3600:
        return f'{seconds // 60}m'
    if seconds < 86400:
        return f'{seconds // 3600}h'
    return f'{seconds // 86400}d'
