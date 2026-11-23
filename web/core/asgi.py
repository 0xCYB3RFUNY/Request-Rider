"""
ASGI config for core project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.2/howto/deployment/asgi/
"""

import os

from django.core.asgi import get_asgi_application

from lab.ws_events import project_event_hub

project_event_hub.mark_asgi_active()

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')

django_asgi = get_asgi_application()


async def application(scope, receive, send):
    if scope["type"] == "websocket":
        await project_event_hub.handle_websocket(scope, receive, send)
        return
    await django_asgi(scope, receive, send)
