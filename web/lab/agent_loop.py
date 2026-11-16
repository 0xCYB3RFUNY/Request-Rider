"""Autonomous ReAct Loop Engine for Request-Rider.

Implements iterative multi-turn Reasoning + Action loop:
1. Calls LLM with message history and registered tools.
2. Detects tool calls (or structured JSON action thoughts).
3. Executes tool actions through web.lab.agent_tools.
4. Feeds observation back into LLM context.
5. Emits execution trace steps (Thought -> Action -> Observation -> Final Conclusion).
6. Halts at MAX_STEPS to prevent endless loops.
"""

import json
import logging
from typing import Dict, List, Any, Optional

from .agent_tools import get_available_tools, execute_agent_tool
from .agent_services import (
    get_agent_provider,
    AgentProviderError,
    AgentRequestCancelled,
    _chat_system_prompt,
)

logger = logging.getLogger(__name__)

# Max agent iterations per user prompt to guard token budget and prevent loops
DEFAULT_MAX_STEPS = 6

AGENT_REACT_SYSTEM_PROMPT = """Ти — автономний агент безпеки (Autonomous Security AI Agent) у платформі Request-Rider.
Твоя мета — автономно допомагати оператору досліджувати цілі, аналізувати трафік, тестувати вразливості, виконувати атаки та верифікувати гіпотези безпеки за всіма 15 воркспейсами платформи.

У твоєму розпорядженні є АБСОЛЮТНО ВСІ інструменти платформи (70+ Tools) та каталог навичок (Skills):
- Skills & Методології: skills_list, skills_read (понад 550 спеціалізованих методологій тестування: idor, sqli, ssrf, jwt, xss, bypass тощо).
- Google Harness²: harness2_status, harness2_run_demo, harness_pipeline_info (3-рівневий рекурсивний харнес Propose-Probe-Compose).
- Керування проєктами: project_list, project_create, project_switch_active, project_update, project_delete, project_export, project_import, project_get_knowledge_hub, project_fusion_report, project_hub_task_action.
- Трафік та історія: history_get_records, history_get_transaction_raw, history_search, history_get_record, history_manage, traffic_control (pause/resume/clear/save/annotate), traffic_capture_contexts.
- Ручна відправка та фазинг (Repeater & Intruder): repeater_send_raw_http, repeater_burst_test, repeater_burst_status, repeater_last_byte_sync, repeater_last_byte_status, kebab_send_to_tool, intruder_start_attack, intruder_get_attack_results, intruder_attack_action, intruder_saved_attacks.
- Карта цілі (Target Site Map & 403 Bypass & JS-аналіз): target_run_crawl (static/browser), target_get_sitemap, target_job_action, target_browsers_list, target_js_analyze, bypass_forms_list.
- Сканери безпеки (Active, Corpus, CMS, Reports): scanner_active_start, scanner_job_status, scanner_active_action, scanner_get_findings, scanner_cms_recon, scanner_corpus_stats, scanner_corpus_start, scanner_corpus_action, scanner_report_generate, finding_record, report_ingest.
- OSINT-розвідка та граф знань: osint_recon, osint_transform_list, osint_run_transform, osint_graphs (list/create/get/clear/delete/upsert), osint_transform_job (start/poll/cancel/list_files/read_file).
- Out-of-Band (OAST) детекція: oob_generate, oob_poll, oast_listener (start/poll/stop).
- Трансформації та кодування: data_transform, url_encode, url_decode, base64_encode, base64_decode, random_string, normalize_http.
- Воркфлоу та автоматизація (DAG): workflow_catalog, workflow_manage (CRUD/activate/deactivate), workflow_execute (run/list/cancel/pause/resume/get).
- Маршрутизація та мережа: route_manage (Tor/SOCKS5h/kill switch/route_check), dns_manage (DoH/static hosts/flush).

ПРАВИЛА РОБОТИ У ЦИКЛІ (ReAct Loop):
1. СПОЧАТКУ ПОДУМАЙ (Thought): сформулюй гіпотезу або наступний крок дослідження. Якщо потрібна спеціалізована методологія тестування — спочатку знайди та прочитай відповідний скіл через skills_list / skills_read!
2. ДІЙ (Action): викликай необхідні інструменти платформи для збору фактів, відправки запитів чи аналізу.
3. ПРОАНАЛІЗУЙ СПОСТЕРЕЖЕННЯ (Observation): оціни отримані дані.
4. ПІДСУМОК (Conclusion): надай структурований висновок українською мовою з чіткими доказами.

Не вигадуй дані: завжди використовуй інструменти платформи для отримання реальних результатів!
"""


class AgentStep:
    def __init__(self, step_number: int, thought: str = "", tool_name: str = "", tool_args: Any = None, observation: Any = None):
        self.step_number = step_number
        self.thought = thought
        self.tool_name = tool_name
        self.tool_args = tool_args
        self.observation = observation

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step": self.step_number,
            "thought": self.thought,
            "tool_name": self.tool_name,
            "tool_args": self.tool_args,
            "observation": self.observation,
        }


def _call_provider_turn(provider_instance, messages: List[Dict[str, Any]], tools: List[Dict[str, Any]], cancel_event=None) -> Dict[str, Any]:
    """Execute one turn of LLM completion supporting tool definitions."""
    from urllib.request import Request

    system_prompt = AGENT_REACT_SYSTEM_PROMPT
    
    # Format payload for OpenAI-compatible endpoint
    max_tokens = getattr(provider_instance, "max_tokens", None)
    if not isinstance(max_tokens, int):
        max_tokens = 4096
    payload = {
        "model": provider_instance.model,
        "temperature": 0.1,
        "max_tokens": max_tokens,
        "messages": [
            {"role": "system", "content": system_prompt},
            *messages,
        ],
        "tools": tools,
        "tool_choice": "auto",
    }
    
    payload_bytes = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if provider_instance.api_key:
        headers["Authorization"] = f"Bearer {provider_instance.api_key}"
    if "openrouter" in str(provider_instance.endpoint).lower():
        headers["HTTP-Referer"] = "http://127.0.0.1:8000"
        headers["X-Title"] = "Request-Rider"

    req = Request(provider_instance.endpoint, data=payload_bytes, headers=headers, method="POST")
    data = provider_instance._request_json(req, cancel_event=cancel_event)

    try:
        choice = data["choices"][0]["message"]
        content = choice.get("content") or choice.get("reasoning") or ""
        tool_calls = choice.get("tool_calls") or []
        return {
            "content": content,
            "tool_calls": tool_calls,
            "raw": choice,
        }
    except (KeyError, IndexError, TypeError) as exc:
        raise AgentProviderError("Malformed LLM response format") from exc


def run_agent_loop(
    user_prompt: str,
    provider: str = "ollama",
    context: Optional[Dict[str, Any]] = None,
    max_steps: int = DEFAULT_MAX_STEPS,
    cancel_event=None,
    **provider_config,
) -> Dict[str, Any]:
    """Execute autonomous ReAct loop until task completion or step budget exhaustion.

    Returns:
        {
            "final_answer": str,
            "steps": List[Dict],
            "total_steps": int,
            "completed": bool
        }
    """
    provider_inst = get_agent_provider(provider, **provider_config)
    tools = get_available_tools()

    messages: List[Dict[str, Any]] = []

    # Initial context injection
    attached_evidence = (context or {}).get("attached_evidence")
    if attached_evidence:
        report_sections = []
        regular_evidence = {}
        for key, val in attached_evidence.items():
            if isinstance(val, dict) and (val.get("type") == "file_report" or "data" in val or "report_type" in val):
                fname = val.get("filename") or val.get("name") or key
                rtype = val.get("report_type") or "generic"
                summary = val.get("summary") or ""
                data = val.get("data") or val.get("content") or val.get("text_preview") or {}
                data_str = json.dumps(data, ensure_ascii=False) if not isinstance(data, str) else data
                if len(data_str) > 16000:
                    data_str = data_str[:16000] + "\n... [зміст звіту скорочено для ліміту токенів]"
                report_sections.append(
                    f"### ЗАВАНТАЖЕНИЙ ЗВІТ / ФАЙЛ ОПЕРАТОРА: {fname} (Тип: {rtype})\n"
                    f"Зведення звіту: {summary}\n"
                    f"Знайдені дані (URL, ендпоінти, форми, секрети, знахідки):\n{data_str}"
                )
            else:
                regular_evidence[key] = val

        if report_sections:
            report_prompt = (
                "ОПЕРАТОР НАДАВ ЕКСПОРТОВАНИЙ ЗВІТ ДОСЛІДЖЕННЯ (КРАУЛЕР, СКАНЕР, АУДИТ ТА ЗНАХІДКИ):\n\n"
                + "\n\n".join(report_sections)
                + "\n\nІНСТРУКЦІЯ ДЛЯ АГЕНТА: Уважно вивчи та проаналізуй надані знахідки та ендпоінти зі звіту! "
                "Використовуй виявлені URL, параметри, секрети та форми як першоджерело для планування подальших дій та перевірок за запитом оператора."
            )
            messages.append({"role": "system", "content": report_prompt})

        if regular_evidence:
            messages.append({
                "role": "system",
                "content": f"Selected operator evidence: {json.dumps(regular_evidence, ensure_ascii=False)}"
            })

    messages.append({"role": "user", "content": user_prompt})

    steps: List[AgentStep] = []
    final_answer = ""
    step_num = 0

    while step_num < max_steps:
        if cancel_event and cancel_event.is_set():
            raise AgentRequestCancelled("Agent loop cancelled by user or route switch")

        step_num += 1
        turn_result = _call_provider_turn(provider_inst, messages, tools, cancel_event=cancel_event)

        content = turn_result.get("content", "")
        tool_calls = turn_result.get("tool_calls", [])

        if not tool_calls:
            # Model decided it has enough information to provide the final conclusion
            final_answer = content
            steps.append(AgentStep(
                step_number=step_num,
                thought=content,
                tool_name="none",
                observation="Completed",
            ))
            break

        # Process each tool call requested by the model
        for call in tool_calls:
            call_id = call.get("id") or f"call_{step_num}"
            fn = call.get("function") or {}
            fn_name = fn.get("name")
            fn_args_raw = fn.get("arguments") or "{}"

            if isinstance(fn_args_raw, str):
                try:
                    fn_args = json.loads(fn_args_raw)
                except json.JSONDecodeError:
                    fn_args = {}
            else:
                fn_args = fn_args_raw

            # Execute tool
            observation = execute_agent_tool(fn_name, fn_args, context=context)

            steps.append(AgentStep(
                step_number=step_num,
                thought=content,
                tool_name=fn_name,
                tool_args=fn_args,
                observation=observation,
            ))

            # Append assistant message with tool_calls
            messages.append({
                "role": "assistant",
                "content": content,
                "tool_calls": [call],
            })

            # Append tool result observation
            messages.append({
                "role": "tool",
                "tool_call_id": call_id,
                "name": fn_name,
                "content": json.dumps(observation, ensure_ascii=False),
            })

    if not final_answer and steps:
        final_answer = steps[-1].thought or "Дослідження завершено або досягнуто ліміт кроків."

    return {
        "final_answer": final_answer,
        "steps": [s.to_dict() for s in steps],
        "total_steps": step_num,
        "completed": bool(final_answer),
    }
