from dashboard.models import *
from django.conf import settings


def projects(request):
    projects = Project.objects.all()
    try:
        slug = request.resolver_match.kwargs.get('slug')
        project = Project.objects.get(slug=slug)
    except Exception:
        project = None
    out = {
        'projects': projects,
        'current_project': project
    }
    if project is not None:  # the header's 'Current portfolio' menu: the project's portfolios and the session's pick
        from limes import portfolios
        options = list(project.portfolios.order_by('name').values('id', 'name'))
        pick = portfolios.picked_id(request, project)
        out.update({'portfolio_options': options, 'current_portfolio': next((o for o in options if o['id'] == pick), None)})
    return out

def version_context(request):
    return {
        'LIMES_CURRENT_VERSION': settings.LIMES_CURRENT_VERSION,
        'MCP_ENABLED': settings.MCP_ENABLED,
    }

