from django.shortcuts import get_object_or_404, render
from django.utils import timezone

from dashboard import home
from dashboard.models import Project


def home_page(request, slug):
    project = get_object_or_404(Project, slug=slug)
    return render(request, 'dashboard/home.html', {'home_active': 'active', **home.build(project, request.user, timezone.now())})
