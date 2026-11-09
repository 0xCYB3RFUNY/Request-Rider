import asyncio
import json
from collections import defaultdict


class ProjectEventHub:
    def __init__(self):
        self._subscribers = defaultdict(set)
        self._loop = None
        self._asgi_active = False

    @property
    def websocket_supported(self):
        return self._asgi_active

    def mark_asgi_active(self):
        self._asgi_active = True

    def set_loop(self, loop):
        self._loop = loop

    async def _accept(self, project_id, send):
        self._subscribers[project_id].add(send)

    async def _disconnect(self, project_id, send):
        subscribers = self._subscribers.get(project_id, set())
        subscribers.discard(send)
        if not subscribers:
            self._subscribers.pop(project_id, None)

    async def handle_websocket(self, scope, receive, send):
        path = scope.get("path", "")
        parts = [segment for segment in path.split("/") if segment]
        if len(parts) < 4 or parts[0] != "ws" or parts[1] != "project" or parts[3] != "events":
            await send({"type": "websocket.close", "code": 1008})
            return
        project_id = parts[2]
        try:
            int(project_id)
        except ValueError:
            await send({"type": "websocket.close", "code": 1008})
            return
        self._loop = asyncio.get_running_loop()
        await self._accept(project_id, send)
        await send({"type": "websocket.accept"})
        try:
            while True:
                message = await receive()
                if message["type"] == "websocket.disconnect":
                    break
        except Exception:
            pass
        finally:
            await self._disconnect(project_id, send)

    async def broadcast(self, project_id, event):
        if project_id is None:
            return
        if isinstance(event, dict):
            payload = {"type": "project_event", **event}
        else:
            payload = {"type": "project_event", "message": str(event)}
        frame = json.dumps(payload, ensure_ascii=False)
        subscribers = list(self._subscribers.get(str(project_id), set()))
        for subscriber in subscribers:
            try:
                await subscriber({"type": "websocket.send", "text": frame})
            except Exception:
                pass

    def emit(self, project_id, event):
        if project_id is None:
            return
        if self._loop is None or not self._loop.is_running():
            return
        try:
            asyncio.run_coroutine_threadsafe(self.broadcast(str(project_id), event), self._loop)
        except RuntimeError:
            pass


project_event_hub = ProjectEventHub()


def emit_project_event(project_id, event):
    project_event_hub.emit(project_id, event)
