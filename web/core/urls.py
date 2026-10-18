"""
URL configuration for core project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.conf import settings
from django.urls import path
from django.views.static import serve
from lab import views
from lab import scanner_report_views
from lab import active_scanner_views

urlpatterns = [
    # `admin/` was the default route from `startproject` and it was never used.
    # It resolved to a login form with no account behind it: `User.objects` was
    # empty and `lab/admin.py` still held its generated placeholder comment, so
    # the model registry it guarded was empty too. `django.contrib.admin` is
    # removed from INSTALLED_APPS with it, because the two are only ever used
    # together and leaving the app installed buys nothing but the `/admin/login/`
    # page and its static assets.
    #
    # The route map is not documentation: with DEBUG on, any unmatched path
    # printed all 73 of these names. Both halves are now closed.
    #
    # The vendored Cytoscape bundle. Served from the repository, pinned by the
    # version in the file name; the page must not depend on a CDN.
    #
    # The capture group is named `path`, not `filename`: Django 5.2's signature
    # is `serve(request, path, document_root=None, show_indexes=False)`, so a
    # `<path:filename>` pattern raises `TypeError: serve() got an unexpected
    # keyword argument 'filename'` and the request 500s. That never showed up
    # while DEBUG was on, because `runserver` answers `/static/` itself from
    # STATICFILES_DIRS before the URLconf is consulted — the route was dead, and
    # the runserver static handler was what actually served the bundle. Turning
    # DEBUG off removed the mask and exposed it, which is why the bundle has to
    # be checked on every non-DEBUG server (gunicorn, uwsgi, `runserver
    # --insecure`) rather than assumed to work from a debug-mode run.
    path('static/vendor/<path:path>', serve, {'document_root': settings.BASE_DIR / 'static' / 'vendor'}, name='vendor-bundle'),
    path('', views.index, name='index'),
    # The gateway's liveness endpoint. It was missing while the engine
    # (`engine/main.go`) and the browser worker both published one, so anything
    # probing the stack's services on a common path list collected `404` from
    # Django on every poll — a log line that said the gateway was down while it
    # was answering the request. It is unauthenticated and read-only, exactly
    # like the other two, and it is the only route here that is not `/api/*`.
    path('health', views.health, name='health'),
    path('api/history', views.history, name='history'),
    path('api/history/export', views.history_export, name='history-export'),
    path('api/history/import', views.history_import, name='history-import'),
    path('api/history/bulk', views.history_bulk, name='history-bulk'),
    path('api/history/<int:record_id>', views.history_detail, name='history-detail'),
    path('api/traffic', views.traffic, name='traffic'),
    path('api/traffic/records', views.traffic_records, name='traffic-records'),
    path('api/traffic/record', views.traffic_record, name='traffic-record'),
    path('api/traffic/detail', views.traffic_detail, name='traffic-detail'),
    path('api/traffic/stream', views.traffic_stream, name='traffic-stream'),
    path('api/traffic/save', views.save_traffic, name='traffic-save'),
    path('api/traffic/annotate', views.annotate_traffic, name='traffic-annotate'),
    path('api/traffic/capture-contexts', views.traffic_capture_contexts, name='traffic-capture-contexts'),
    path('api/traffic/capture-contexts/<int:context_id>', views.traffic_capture_contexts, name='traffic-capture-context-detail'),
    path('api/project-events/status', views.project_event_status, name='project-event-status'),
    path('api/projects', views.projects, name='projects'),
    path('api/projects/import', views.project_import, name='project-import'),
    path('api/projects/<int:project_id>', views.projects, name='project-detail'),
    path('api/projects/<int:project_id>/hub', views.project_hub, name='project-hub'),
    path('api/projects/<int:project_id>/hub/tasks/<str:job_id>/<str:action>', views.project_hub_task_action, name='project-hub-task-action'),
    path('api/projects/<int:project_id>/export', views.project_export, name='project-export'),
    path('api/projects/<int:project_id>/fusion-report', views.project_fusion_report, name='project-fusion-report'),
    path('api/project-context', views.project_context, name='project-context'),
    path('api/execute', views.execute, name='execute'),
    path('api/intruder', views.intruder, name='intruder'),
    path('api/intruder/saved', views.intruder_saved, name='intruder-saved'),
    path('api/intruder/saved/<int:attack_id>', views.intruder_saved, name='intruder-saved-detail'),
    path('api/intruder/saved/<int:attack_id>/run', views.intruder_saved, name='intruder-saved-run'),
    path('api/target-map', views.target_map, name='target-map'),
    path('api/target-map/<str:map_id>', views.target_map, name='target-map-detail'),
    path('api/target-map/<str:map_id>/<str:action>', views.target_map, name='target-map-action'),
    path('api/target-browser', views.target_browser, name='target-browser'),
    path('api/target-browsers', views.target_browsers, name='target-browsers'),
    path('api/osint', views.osint, name='osint'),
    path('api/oast', views.oast_callback, name='oast-callback'),
    path('api/oast/<str:listener_id>', views.oast_callback, name='oast-listener'),
    path('api/osint/graphs', views.osint_graphs, name='osint-graphs'),
    path('api/osint/transforms', views.osint_transform_registry, name='osint-transform-registry'),
    path('api/bypass/forms', views.bypass_forms_registry, name='bypass-forms-registry'),
    path('api/osint/graphs/<int:graph_id>/upsert', views.osint_graph_upsert, name='osint-graph-upsert'),
    path('api/osint/graphs/<int:graph_id>/transform', views.osint_graph_transform, name='osint-graph-transform'),
    path('api/osint/graphs/<int:graph_id>/transform/jobs', views.osint_graph_transform_job, name='osint-graph-transform-jobs'),
    path('api/osint/graphs/<int:graph_id>/transform/jobs/<str:job_id>', views.osint_graph_transform_job, name='osint-graph-transform-job'),
    path('api/osint/graphs/<int:graph_id>/transform/jobs/<str:job_id>/<str:action>', views.osint_graph_transform_job, name='osint-graph-transform-job-action'),
    # The directory form carries a trailing slash so that both `/files` and the
    # `/files/` an analyst types reach it: APPEND_SLASH only adds a slash, it
    # never removes one, so a slashless route would leave the slash form a 404.
    path('api/osint/graphs/<int:graph_id>/files/', views.osint_graph_files, name='osint-graph-files'),
    path('api/osint/graphs/<int:graph_id>/files/<str:name>', views.osint_graph_file, name='osint-graph-file'),
    path('api/osint/graphs/<int:graph_id>/clear', views.osint_graph_clear, name='osint-graph-clear'),
    path('api/osint/graphs/<int:graph_id>/entities/<int:entity_id>', views.osint_graph_entity, name='osint-graph-entity'),
    path('api/osint/graphs/<int:graph_id>/relations/<int:relation_id>', views.osint_graph_relation, name='osint-graph-relation'),
    path('api/osint/graphs/<int:graph_id>', views.osint_graphs, name='osint-graph-detail'),
    path('api/scanner', views.scanner, name='scanner'),
    path('api/scanner/nuclei', views.scanner_nuclei, name='scanner-nuclei'),
    path('api/scanner/nuclei/upload', views.scanner_nuclei_upload, name='scanner-nuclei-upload'),
    path('api/scanner/nuclei/run', views.scanner_nuclei_run, name='scanner-nuclei-run'),
    path('api/scanner/nuclei/dirs', views.scanner_nuclei_template_dirs, name='scanner-nuclei-dirs'),
    path('api/scanner/nuclei/inspect', views.scanner_nuclei_template_inspect, name='scanner-nuclei-inspect'),
    path('api/scanner/nuclei/run-dir', views.scanner_nuclei_run_dir, name='scanner-nuclei-run-dir'),
    path('api/scanner/nuclei/jobs-dir', views.scanner_nuclei_template_dir_job, name='scanner-nuclei-jobs-dir'),
    path('api/scanner/nuclei/local', views.scanner_nuclei_local, name='scanner-nuclei-local'),
    path('api/scanner/nuclei/jobs', views.scanner_nuclei_jobs, name='scanner-nuclei-jobs'),
    path('api/scanner/nuclei/jobs/<str:job_id>', views.scanner_nuclei_jobs, name='scanner-nuclei-job'),
    path('api/scanner/corpus/stats', views.scanner_corpus_stats, name='scanner-corpus-stats'),
    path('api/scanner/corpus/run', views.scanner_corpus_run, name='scanner-corpus-run'),
    path('api/scanner/corpus/jobs', views.scanner_corpus_jobs, name='scanner-corpus-jobs'),
    path('api/scanner/corpus/jobs/<str:job_id>', views.scanner_corpus_jobs, name='scanner-corpus-job'),
    path('api/scanner/corpus/jobs/<str:job_id>/stream', views.scanner_corpus_job_stream, name='scanner-corpus-job-stream'),
    # The stream route is declared first: it would otherwise be swallowed by the
    # generic action route, which only knows cancel, pause and resume.
    path('api/scanner/nuclei/jobs/<str:job_id>/stream', views.scanner_nuclei_job_stream, name='scanner-nuclei-job-stream'),
    path('api/scanner/nuclei/jobs/<str:job_id>/<str:action>', views.scanner_nuclei_jobs, name='scanner-nuclei-job-action'),
    # The active scanner is an asynchronous run like the template scan, so it gets
    # the same job shape: start, poll, stream and cancel. Its view lives in its own
    # module because `views.py` is shared; the wiring here is one import and these
    # three routes.
    path('api/scanner/active/jobs', active_scanner_views.scanner_active_jobs, name='scanner-active-jobs'),
    path('api/scanner/active/jobs/<str:job_id>', active_scanner_views.scanner_active_jobs, name='scanner-active-job'),
    path('api/scanner/active/jobs/<str:job_id>/stream', active_scanner_views.scanner_active_job_stream, name='scanner-active-job-stream'),
    path('api/scanner/active/jobs/<str:job_id>/<str:action>', active_scanner_views.scanner_active_jobs, name='scanner-active-job-action'),
    # The report is rendered here, on the server, rather than assembled in the
    # browser. It lives in its own module because another session holds
    # `views.py`; the only wiring it needs from this file is this one line.
    path('api/scanner/report', scanner_report_views.scanner_report, name='scanner-report'),
    path('api/agent/chat', views.agent_chat, name='agent-chat'),
    path('api/agent/run', views.agent_run, name='agent-run'),
    path('api/workflows/node-types', views.workflow_node_types, name='workflow-node-types'),
    path('api/workflow-templates', views.workflow_templates, name='workflow-templates'),
    path('api/workflows/hooks/<slug:slug>', views.workflow_webhook, name='workflow-webhook'),
    path('api/workflows/import', views.workflow_import, name='workflow-import'),
    path('api/workflows/runs/<int:run_id>/stream', views.workflow_run_stream, name='workflow-run-stream'),
    path('api/workflows/runs/<int:run_id>/export', views.workflow_run_export, name='workflow-run-export'),
    path('api/workflows/runs/<int:run_id>/<str:action>', views.workflow_run_action, name='workflow-run-action'),
    path('api/workflows/runs/<int:run_id>', views.workflow_runs, name='workflow-run-detail'),
    path('api/workflows/runs', views.workflow_runs, name='workflow-runs'),
    path('api/workflows/<int:workflow_id>/activate', views.workflow_activation, name='workflow-activate'),
    path('api/workflows/<int:workflow_id>/deactivate', views.workflow_deactivation, name='workflow-deactivate'),
    path('api/workflows/<int:workflow_id>/run', views.workflow_run, name='workflow-run'),
    path('api/workflows/<int:workflow_id>/export', views.workflow_export, name='workflow-export'),
    path('api/workflows/<int:workflow_id>', views.workflows, name='workflow-detail'),
    path('api/workflows', views.workflows, name='workflows'),
    path('api/route', views.route, name='route'),
    path('api/route/check', views.route_check, name='route-check'),
]
