from django.core.cache import cache
from django.db import connection
from django.http import JsonResponse


def healthz(request):
    failed = []
    try:
        with connection.cursor() as cursor:
            cursor.execute('SELECT 1')
    except Exception:
        failed.append('database')
    try:
        cache.set('healthz', 1, 5)
    except Exception:
        failed.append('cache')
    if failed:
        return JsonResponse({'status': 'error', 'failed': failed}, status=503)
    return JsonResponse({'status': 'ok'})
