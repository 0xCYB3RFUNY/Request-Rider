FROM mcr.microsoft.com/playwright/python:v1.55.0-noble@sha256:640d578aae63cfb632461d1b0aecb01414e4e020864ac3dd45a868dc0eff3078
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# firefox, chromium and webkit ship with Playwright itself. `chrome` and
# `msedge` are separate system browsers that the image must download, because
# launch_browser() selects them with channel="chrome" / channel="msedge" rather
# than a Playwright build, and worker.py advertises all five in /health - so
# without this line the UI offers two browsers that cannot start in Docker.
RUN playwright install --with-deps firefox chromium webkit \
 && playwright install --with-deps chrome msedge
# The worker imports its own siblings by bare name (`import human_input`), and
# `python -c` puts the current directory on `sys.path` while the container does
# not copy the whole tree. A missing sibling is therefore not a soft failure: it
# is `ModuleNotFoundError` at import time, the container dies on startup, and the
# service crash-loops, which leaves `web` with no browser at all. Measured on a
# containerised stand 2026-10-01: the list was written out by hand, each omission
# cost a full image rebuild to find.
#
# So the list is derived, not remembered: every local module `worker.py` imports
# is copied, and the AST walk in the commit that added it yields exactly these.
COPY worker.py anti_detect.py chromium_fonts.py human_input.py proxy_pool.py .
EXPOSE 8090
CMD ["python", "worker.py"]
