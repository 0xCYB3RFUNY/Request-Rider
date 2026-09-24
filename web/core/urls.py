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
from django.contrib import admin
from django.urls import path
from lab import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.index, name='index'),
    path('api/history', views.history, name='history'),
    path('api/history/export', views.history_export, name='history-export'),
    path('api/history/import', views.history_import, name='history-import'),
    path('api/history/bulk', views.history_bulk, name='history-bulk'),
    path('api/history/<int:record_id>', views.history_detail, name='history-detail'),
    path('api/traffic', views.traffic, name='traffic'),
    path('api/traffic/stream', views.traffic_stream, name='traffic-stream'),
    path('api/traffic/save', views.save_traffic, name='traffic-save'),
    path('api/traffic/annotate', views.annotate_traffic, name='traffic-annotate'),
    path('api/traffic/capture-contexts', views.traffic_capture_contexts, name='traffic-capture-contexts'),
    path('api/traffic/capture-contexts/<int:context_id>', views.traffic_capture_contexts, name='traffic-capture-context-detail'),
    path('api/projects', views.projects, name='projects'),
    path('api/projects/<int:project_id>', views.projects, name='project-detail'),
    path('api/projects/<int:project_id>/hub', views.project_hub, name='project-hub'),
    path('api/project-context', views.project_context, name='project-context'),
    path('api/findings', views.findings, name='findings'),
    path('api/findings/<int:finding_id>/attach', views.attach_finding_to_active_project, name='finding-attach'),
    path('api/findings/<int:finding_id>/verify', views.verify_finding, name='finding-verify'),
    path('api/findings/<int:finding_id>', views.findings, name='finding-detail'),
    path('api/findings/export', views.findings_export, name='findings-export'),
    path('api/execute', views.execute, name='execute'),
    path('api/intruder', views.intruder, name='intruder'),
    path('api/intruder/saved', views.intruder_saved, name='intruder-saved'),
    path('api/intruder/saved/<int:attack_id>', views.intruder_saved, name='intruder-saved-detail'),
    path('api/intruder/saved/<int:attack_id>/run', views.intruder_saved, name='intruder-saved-run'),
    path('api/target-map', views.target_map, name='target-map'),
    path('api/target-browser', views.target_browser, name='target-browser'),
    path('api/osint', views.osint, name='osint'),
    path('api/osint/graphs', views.osint_graphs, name='osint-graphs'),
    path('api/osint/transforms', views.osint_transform_registry, name='osint-transform-registry'),
    path('api/osint/graphs/<int:graph_id>/upsert', views.osint_graph_upsert, name='osint-graph-upsert'),
    path('api/osint/graphs/<int:graph_id>/transform', views.osint_graph_transform, name='osint-graph-transform'),
    path('api/osint/graphs/<int:graph_id>', views.osint_graphs, name='osint-graph-detail'),
    path('api/scanner', views.scanner, name='scanner'),
    path('api/agent/chat', views.agent_chat, name='agent-chat'),
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
