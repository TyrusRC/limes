"""Subsidiaries and portfolios over REST, project-scoped like the tag API. Reading is open to any signed-in user;
writing needs the modify-targets permission. Picking the current portfolio is a personal view setting (the session),
so it needs only a signed-in user. An id or name from another project is a 404; a bad value is a 400."""
from rest_framework.response import Response
from rest_framework.views import APIView

from api.permissions import HasPermission
from dashboard.models import Project
from limes import portfolios, subsidiaries
from limes.definitions import PERM_MODIFY_TARGETS


def _args(request):
    body = request.data if isinstance(request.data, dict) else {}
    if request.method == 'GET':
        return request.query_params.dict()
    return {**request.query_params.dict(), **body} if request.method == 'DELETE' else body


def _project(args):
    return Project.objects.filter(slug=args['project']).first() if isinstance(args.get('project'), str) else None


class _Base(APIView):
    """GET is open; every other method needs PERM_MODIFY_TARGETS unless the view says `write_open`."""
    write_open = False

    permission_required = PERM_MODIFY_TARGETS

    def get_permissions(self):
        if self.request.method in ('GET', 'HEAD', 'OPTIONS') or self.write_open:
            return super().get_permissions()
        return [HasPermission()]

    def handle(self, request, fn):
        args = _args(request)
        project = _project(args)
        if not project:
            return Response({'status': False, 'message': 'project not found'}, status=404)
        try:
            return fn(project, args)
        except subsidiaries.NotFound as e:
            return Response({'status': False, 'message': str(e)}, status=404)
        except subsidiaries.SubsidiaryError as e:
            return Response({'status': False, 'message': str(e)}, status=400)


class SubsidiaryList(_Base):
    """GET: every subsidiary with its own score. POST {project, name}: create. DELETE {project, name}: remove (its assets
    return to the organization). A subsidiary's score never changes the project's headline."""

    def get(self, request):
        return self.handle(request, lambda project, a: Response(subsidiaries.scores(project)))

    def post(self, request):
        def run(project, a):
            sub = subsidiaries.create(project, a.get('name'))
            return Response({'status': True, 'id': sub.id, 'name': sub.name}, status=201)
        return self.handle(request, run)

    def delete(self, request):
        def run(project, a):
            subsidiaries.delete(project, a.get('name'))
            return Response({'status': True})
        return self.handle(request, run)


class AssignSubsidiary(_Base):
    """POST {project, subsidiary (name, or null for the organization), assets: [ids]}: all or nothing."""

    def post(self, request):
        def run(project, a):
            n = subsidiaries.assign(project, a.get('subsidiary'), a.get('assets'))
            return Response({'status': True, 'assets': n})
        return self.handle(request, run)


class PortfolioList(_Base):
    """GET: the project's portfolios. POST {project, name, tags?, subsidiary?, assets?}: save one. DELETE {project, id}."""

    def get(self, request):
        return self.handle(request, lambda project, a: Response(portfolios.listing(project)))

    def post(self, request):
        def run(project, a):
            p = portfolios.create(project, a.get('name'), a.get('tags'), a.get('subsidiary'), a.get('assets'))
            return Response({'status': True, 'id': p.id, 'name': p.name}, status=201)
        return self.handle(request, run)

    def delete(self, request):
        def run(project, a):
            pid = a.get('id')
            pid = int(pid) if isinstance(pid, str) and pid.isascii() and pid.isdigit() else pid
            portfolios.get(project, pid).delete()
            return Response({'status': True})
        return self.handle(request, run)


class SelectPortfolio(_Base):
    """POST {project, portfolio: id or null}: the session's current portfolio for that project."""
    write_open = True

    def post(self, request):
        def run(project, a):
            pid = a.get('portfolio')
            portfolios.select(request, project, pid if pid is None or isinstance(pid, int) else -1)
            return Response({'status': True})
        return self.handle(request, run)
