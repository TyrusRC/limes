"""REST for collaboration notes. Project-scoped: the target and the note are looked up inside the named project, so an id
from another project is a 404. Reads are login-only; creating needs PERM_MODIFY_TARGETS; deleting is the author's only."""
from rest_framework.response import Response
from rest_framework.views import APIView

from remediation import notes
from remediation.api import Writer, _bad, _id, _missing, _project


def note_json(n):
    return {'id': n['id'], 'author': n['author'], 'body': n['body'], 'created_at': n['created_at'], 'mine': n['mine']}


def _target(data):
    project, kind, pk = _project(data), data.get('type'), _id(data.get('id'))
    if project is None or kind not in notes.TYPES or pk is None or notes.target(project, kind, pk) is None:
        return None, None, None
    return project, kind, pk


class NoteList(APIView):
    def get(self, request):
        project, kind, pk = _target(request.query_params)
        if project is None:
            return _missing()
        return Response([note_json(n) for n in notes.timeline(project, kind, pk, request.user)])


class NoteCreate(Writer):
    def post(self, request):
        data = request.data if isinstance(request.data, dict) else {}
        project, kind, pk = _target(data)
        if project is None:
            return _missing()
        try:
            note = notes.add(project, request.user, kind, pk, data.get('body'))
        except notes.NotFound:
            return _missing()
        except notes.NoteError as e:
            return Response({'status': False, 'message': str(e)}, status=429 if 'too many' in str(e) else 400)
        return Response({'status': True, 'id': note.id})


class NoteDelete(APIView):
    def post(self, request):
        data = request.data if isinstance(request.data, dict) else {}
        project, nid = _project(data), _id(data.get('note_id'))
        if project is None or nid is None:
            return _missing()
        try:
            notes.delete(project, request.user, nid)
        except notes.NotFound:
            return _missing()
        except PermissionError as e:
            return Response({'status': False, 'message': str(e)}, status=403)
        return Response({'status': True})
