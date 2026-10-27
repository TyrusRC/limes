from django.template.loader import render_to_string


def snapshot(d):
    """Self-contained HTML (inline CSS, no script, no external URL) of the summary data; autoescaped."""
    return render_to_string('reporting/snapshot.html', {'d': d})
