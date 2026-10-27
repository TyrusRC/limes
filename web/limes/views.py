import os
import mimetypes
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, Http404
from django.conf import settings

from memberships import rules

def _report_project_id(path):
    """The project id in reports/<project id>/<file>, else None."""
    parts = path.split('/')
    return int(parts[1]) if len(parts) > 2 and parts[0] == 'reports' and parts[1].isdigit() else None


@login_required
def serve_protected_media(request, path):
    # Stored report snapshots belong to one project: only its members get them. NOTE: scan result folders are named
    # by target, not by project, so they stay readable by every signed-in user. Upgrade path: address them by project id.
    if '..' in path.split('/'):
        raise Http404("File not found")
    pid = _report_project_id(path)
    if pid is not None and rules.role_for(request.user, pid) is None:
        raise Http404("File not found")
    file_path = os.path.join(settings.MEDIA_ROOT, path)
    if os.path.isdir(file_path):
        raise Http404("File not found")
    if os.path.exists(file_path):
        content_type, _ = mimetypes.guess_type(file_path)
        response = HttpResponse()
        # response['Content-Disposition'] = f'attachment; filename={os.path.basename(file_path)}'
        response['Content-Type'] = content_type
        response['X-Accel-Redirect'] = f'/protected_media/{path}'
        return response
    else:
        raise Http404("File not found")

