"""Request middleware for the validated server-side active Project context."""

from .models import Project


ACTIVE_PROJECT_SESSION_KEY = "active_project_id"


class ActiveProjectMiddleware:
    """Attach a validated active Project without trusting request parameters."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        project = None
        raw_project_id = request.session.get(ACTIVE_PROJECT_SESSION_KEY)
        if raw_project_id not in (None, ""):
            try:
                project_id = int(raw_project_id)
            except (TypeError, ValueError):
                project_id = 0
            if project_id > 0:
                project = Project.objects.filter(id=project_id).first()
            if project is None:
                request.session.pop(ACTIVE_PROJECT_SESSION_KEY, None)
                request.session.modified = True
        request.active_project = project
        return self.get_response(request)
