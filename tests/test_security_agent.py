"""Tests unitarios y de propiedad del SecurityAgent (Tarea 8.2 - 8.6).

Tareas cubiertas:
  8.2 - Tests unitarios: CVE omitido sin manifiestos, tope de 20, no_evaluado
        en fallo LLM, descartado para no explotables, dry-run omite comment.
  8.3 - Property 1: Hallazgos no explotables siempre se descartan.
  8.4 - Property 2: analysis_id es UUID v4 válido en todos los eventos de log.
  8.5 - Property 3: confirmed_findings siempre ordenados por severidad desc.
  8.6 - Property 4: Invocaciones al LLM nunca superan min(candidatos, 20).

Estrategia:
  - Todos los puertos se mockean con unittest.mock.AsyncMock.
  - Ningún test llama a infraestructura real.
"""

from __future__ import annotations

import io
import re
import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from security_pr_guardian.core.agent import SecurityAgent, MAX_FINDINGS_LLM
from security_pr_guardian.core.models import (
    AnalysisResult,
    AppConfig,
    CandidateFinding,
    ConfirmedFinding,
    CVEFinding,
    KBFragment,
    LLMVerdict,
    Recommendation,
    Severity,
    SEVERITY_ORDER,
    StaticAnalysisResult,
)
from security_pr_guardian.core.logger import StructuredLogger

# ---------------------------------------------------------------------------
# Helpers y factories
# ---------------------------------------------------------------------------

UUID_V4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)

DIFF_NO_MANIFEST = """\
diff --git a/app/main.py b/app/main.py
--- a/app/main.py
+++ b/app/main.py
@@ -1,3 +1,4 @@
+query = f"SELECT * FROM users WHERE id = {user_id}"
"""

DIFF_WITH_MANIFEST = """\
diff --git a/requirements.txt b/requirements.txt
--- a/requirements.txt
+++ b/requirements.txt
@@ -1,2 +1,3 @@
+requests==2.28.0
diff --git a/app/main.py b/app/main.py
--- a/app/main.py
+++ b/app/main.py
@@ -1,3 +1,4 @@
+query = f"SELECT * FROM users WHERE id = {user_id}"
"""


def make_config(**overrides) -> AppConfig:
    """Crea un AppConfig válido para tests, sin leer .env ni variables de entorno."""
    defaults = {
        "github_token": "ghp_test",
        "llm_backend": "bedrock",
        "bedrock_region": "us-east-1",
        "bedrock_model_id": "anthropic.claude-3-sonnet-20240229-v1:0",
    }
    defaults.update(overrides)
    # _env_file=None evita leer .env; ignoramos variables de entorno del sistema
    return AppConfig(_env_file=None, **defaults)


def make_candidate(
    severity: Severity = Severity.HIGH,
    source: str = "static",
    cwe_id: str = "CWE-89",
) -> CandidateFinding:
    """Crea un CandidateFinding para tests."""
    return CandidateFinding(
        source=source,
        tipo_vulnerabilidad="SQL Injection",
        archivo="app/db.py",
        linea_inicio=10,
        linea_fin=10,
        fragmento_codigo='query = f"SELECT * FROM users WHERE id = {user_id}"',
        patron_detectado="CWE-89",
        cwe_id=cwe_id,
        severidad_inicial=severity,
    )


def make_verdict(explotable: bool = True, severity: Severity = Severity.HIGH) -> LLMVerdict:
    """Crea un LLMVerdict para tests."""
    return LLMVerdict(
        es_explotable=explotable,
        severidad_ajustada=severity,
        justificacion=(
            "El input del usuario llega sin sanitizar directamente a la "
            "consulta SQL, permitiendo inyección arbitraria de comandos SQL."
        ),
        recomendacion=Recommendation(
            descripcion="Usar consultas parametrizadas.",
            codigo_corregido='cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
            referencia="CWE-89",
        ),
    )


def make_kb_fragment() -> KBFragment:
    return KBFragment(
        titulo="CWE-89: SQL Injection",
        contenido="SQL Injection occurs when user input is not sanitized.",
        fuente="CWE",
        score_relevancia=0.9,
    )


def build_agent(
    diff: str = DIFF_NO_MANIFEST,
    sast_findings: list[CandidateFinding] | None = None,
    cve_findings: list[Any] | None = None,
    llm_side_effect=None,
    comment_id: str = "123",
    log_output: io.StringIO | None = None,
) -> tuple[SecurityAgent, AppConfig]:
    """Construye un SecurityAgent con todos los puertos mockeados."""
    if sast_findings is None:
        sast_findings = []
    if cve_findings is None:
        cve_findings = []

    config = make_config()

    # Logger que escribe en StringIO para poder inspeccionar eventos
    analysis_id = str(uuid.uuid4())
    logger = StructuredLogger(analysis_id, output=log_output or io.StringIO())

    diff_port = AsyncMock()
    diff_port.get_diff.return_value = diff

    static_port = AsyncMock()
    static_port.analyze_diff.return_value = StaticAnalysisResult(findings=sast_findings)

    cve_port = AsyncMock()
    cve_port.lookup_vulnerabilities.return_value = cve_findings

    kb_port = AsyncMock()
    kb_port.retrieve.return_value = [make_kb_fragment()]

    llm_port = AsyncMock()
    if llm_side_effect is not None:
        llm_port.evaluate_finding.side_effect = llm_side_effect
    else:
        llm_port.evaluate_finding.return_value = make_verdict(explotable=True)

    comment_port = AsyncMock()
    comment_port.post_or_update_comment.return_value = comment_id

    agent = SecurityAgent(
        config=config,
        diff_extraction_port=diff_port,
        static_analysis_port=static_port,
        cve_lookup_port=cve_port,
        kb_retrieval_port=kb_port,
        llm_reasoning_port=llm_port,
        pr_comment_port=comment_port,
        logger=logger,
    )
    return agent, config


# ---------------------------------------------------------------------------
# Tarea 8.2 — Tests unitarios
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cve_skipped_when_no_manifests():
    """
    DADO: Un diff sin manifiestos de dependencias.
    CUANDO: se ejecuta run().
    ENTONCES: lookup_vulnerabilities NO se llama nunca.
    """
    agent, _ = build_agent(diff=DIFF_NO_MANIFEST)
    await agent.run(repo="owner/repo", pr_number=1)

    agent.cve_lookup_port.lookup_vulnerabilities.assert_not_called()


@pytest.mark.asyncio
async def test_cve_called_when_manifests_present():
    """
    DADO: Un diff con requirements.txt modificado.
    CUANDO: se ejecuta run().
    ENTONCES: lookup_vulnerabilities SÍ se llama.
    """
    agent, _ = build_agent(diff=DIFF_WITH_MANIFEST)
    await agent.run(repo="owner/repo", pr_number=1)

    agent.cve_lookup_port.lookup_vulnerabilities.assert_called_once()


@pytest.mark.asyncio
async def test_llm_cap_of_20_findings():
    """
    DADO: 25 CandidateFindings de SAST.
    CUANDO: se ejecuta run().
    ENTONCES: evaluate_finding se llama exactamente 20 veces (tope).
    """
    candidates = [make_candidate() for _ in range(25)]
    agent, _ = build_agent(sast_findings=candidates)
    await agent.run(repo="owner/repo", pr_number=1)

    assert agent.llm_reasoning_port.evaluate_finding.call_count == 20


@pytest.mark.asyncio
async def test_no_evaluado_when_llm_raises():
    """
    DADO: El LLM lanza excepción en todos los findings.
    CUANDO: se ejecuta run().
    ENTONCES: todos los ConfirmedFindings tienen disposition='no_evaluado'.
    """
    candidates = [make_candidate(), make_candidate()]
    agent, _ = build_agent(
        sast_findings=candidates,
        llm_side_effect=RuntimeError("Bedrock timeout"),
    )
    result = await agent.run(repo="owner/repo", pr_number=1)

    assert all(f.disposition == "no_evaluado" for f in result.confirmed_findings)
    assert result.not_evaluated_count == 2


@pytest.mark.asyncio
async def test_discarded_for_non_exploitable():
    """
    DADO: El LLM retorna es_explotable=False para todos los findings.
    CUANDO: se ejecuta run().
    ENTONCES: disposition='descartado' en todos los ConfirmedFindings.
    """
    candidates = [make_candidate(), make_candidate()]
    agent, _ = build_agent(
        sast_findings=candidates,
        llm_side_effect=None,
    )
    agent.llm_reasoning_port.evaluate_finding.return_value = make_verdict(explotable=False)
    result = await agent.run(repo="owner/repo", pr_number=1)

    assert all(f.disposition == "descartado" for f in result.confirmed_findings)
    assert result.discarded_count == 2


@pytest.mark.asyncio
async def test_dry_run_omits_comment_port():
    """
    DADO: dry_run=True.
    CUANDO: se ejecuta run().
    ENTONCES: post_or_update_comment NO se llama.
    """
    agent, _ = build_agent(sast_findings=[make_candidate()])
    result = await agent.run(repo="owner/repo", pr_number=1, dry_run=True)

    agent.pr_comment_port.post_or_update_comment.assert_not_called()
    assert result.comment_id is None


@pytest.mark.asyncio
async def test_dry_run_false_calls_comment_port():
    """
    DADO: dry_run=False (default).
    CUANDO: se ejecuta run().
    ENTONCES: post_or_update_comment SÍ se llama y comment_id queda en el resultado.
    """
    agent, _ = build_agent(sast_findings=[make_candidate()], comment_id="456")
    result = await agent.run(repo="owner/repo", pr_number=1, dry_run=False)

    agent.pr_comment_port.post_or_update_comment.assert_called_once()
    assert result.comment_id == "456"


# ---------------------------------------------------------------------------
# Tarea 8.3 — Property 1: No explotables siempre descartados
# ---------------------------------------------------------------------------

@given(
    verdicts=st.lists(st.booleans(), min_size=0, max_size=20),
)
@settings(max_examples=100)
def test_property_non_exploitable_always_discarded(verdicts: list[bool]):
    """
    Property 1: Todo finding con es_explotable=False tiene disposition='descartado'
    y no aparece en confirmed_findings con disposition='incluido'.
    """
    import asyncio

    candidates = [make_candidate() for _ in verdicts]
    verdict_objects = [make_verdict(explotable=v) for v in verdicts]

    log_output = io.StringIO()
    agent, _ = build_agent(sast_findings=candidates, log_output=log_output)
    agent.llm_reasoning_port.evaluate_finding.side_effect = verdict_objects

    result = asyncio.run(
        agent.run(repo="owner/repo", pr_number=1, dry_run=True)
    )

    for finding, expected_exploitable in zip(result.confirmed_findings, verdicts):
        if not expected_exploitable:
            assert finding.disposition == "descartado", (
                f"Finding con es_explotable=False tiene disposition={finding.disposition}"
            )
        else:
            assert finding.disposition == "incluido"

    # Los descartados no deben aparecer en la lista con disposition='incluido'
    included = [f for f in result.confirmed_findings if f.disposition == "incluido"]
    assert all(f.disposition == "incluido" for f in included)


# ---------------------------------------------------------------------------
# Tarea 8.4 — Property 2: analysis_id es UUID v4 en todos los log events
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_property_analysis_id_is_uuid_v4():
    """
    Property 2: Todos los eventos de log contienen analysis_id con formato UUID v4.
    """
    log_output = io.StringIO()
    agent, _ = build_agent(
        sast_findings=[make_candidate()],
        log_output=log_output,
    )
    # Reemplazar el logger interno de run para capturar los eventos
    # Ejecutamos run y capturamos los logs escritos en el StringIO
    await agent.run(repo="owner/repo", pr_number=1, dry_run=True)

    log_output.seek(0)
    import json as _json
    for line in log_output.read().splitlines():
        if not line.strip():
            continue
        event = _json.loads(line)
        assert "analysis_id" in event, f"Evento sin analysis_id: {event}"
        assert UUID_V4_RE.match(event["analysis_id"]), (
            f"analysis_id no es UUID v4: {event['analysis_id']}"
        )


@given(st.integers(min_value=0, max_value=5))
@settings(max_examples=100)
def test_property_analysis_id_uuid_v4_multiple_runs(n_findings: int):
    """
    Property 2 (PBT): Para cualquier número de findings, el analysis_id
    en los logs siempre es UUID v4 válido. Capturamos stderr donde el
    StructuredLogger escribe por defecto.
    """
    import asyncio
    import json as _json
    import sys

    candidates = [make_candidate() for _ in range(n_findings)]
    agent, _ = build_agent(sast_findings=candidates)

    # Capturar stderr donde el logger interno de run() escribe
    captured = io.StringIO()
    original_stderr = sys.stderr
    sys.stderr = captured
    try:
        asyncio.run(
            agent.run(repo="owner/repo", pr_number=1, dry_run=True)
        )
    finally:
        sys.stderr = original_stderr

    captured.seek(0)
    lines = [l for l in captured.read().splitlines() if l.strip()]
    assert len(lines) > 0, "No se emitieron eventos de log"

    for line in lines:
        event = _json.loads(line)
        assert UUID_V4_RE.match(event["analysis_id"]), (
            f"analysis_id no es UUID v4: {event['analysis_id']}"
        )


# ---------------------------------------------------------------------------
# Tarea 8.5 — Property 3: confirmed_findings ordenados por severidad desc
# ---------------------------------------------------------------------------

@given(
    severities=st.lists(
        st.sampled_from(list(Severity)),
        min_size=0,
        max_size=20,
    )
)
@settings(max_examples=100)
def test_property_confirmed_findings_ordered_by_severity_descending(
    severities: list[Severity],
):
    """
    Property 3: El agente ordena los candidatos por severidad descendente
    antes de enviarlos al LLM. Los confirmed_findings mantienen ese orden
    cuando el LLM preserva la severidad inicial.
    """
    import asyncio

    candidates = [make_candidate(severity=s) for s in severities]
    # LLM preserva la misma severidad que el candidato
    verdict_objects = [make_verdict(explotable=True, severity=s) for s in severities]

    agent, _ = build_agent(sast_findings=candidates)
    agent.llm_reasoning_port.evaluate_finding.side_effect = verdict_objects

    result = asyncio.run(
        agent.run(repo="owner/repo", pr_number=1, dry_run=True)
    )

    included = [f for f in result.confirmed_findings if f.disposition == "incluido"]
    # Verificar orden descendente: cada elemento >= el siguiente
    for i in range(len(included) - 1):
        current = SEVERITY_ORDER[included[i].severidad_ajustada]
        next_one = SEVERITY_ORDER[included[i + 1].severidad_ajustada]
        assert current >= next_one, (
            f"Inversión de severidad en posición {i}: "
            f"{included[i].severidad_ajustada} < {included[i+1].severidad_ajustada}"
        )


# ---------------------------------------------------------------------------
# Tarea 8.6 — Property 4: Invocaciones al LLM nunca superan min(candidatos, 20)
# ---------------------------------------------------------------------------

@given(n_candidates=st.integers(min_value=0, max_value=100))
@settings(max_examples=100)
def test_property_llm_invocations_never_exceed_min_candidates_20(n_candidates: int):
    """
    Property 4: El número de llamadas a evaluate_finding nunca supera
    min(len(candidates), 20).
    """
    import asyncio

    candidates = [make_candidate() for _ in range(n_candidates)]
    agent, _ = build_agent(sast_findings=candidates)

    asyncio.run(
        agent.run(repo="owner/repo", pr_number=1, dry_run=True)
    )

    expected_max = min(n_candidates, MAX_FINDINGS_LLM)
    actual_calls = agent.llm_reasoning_port.evaluate_finding.call_count
    assert actual_calls <= expected_max, (
        f"LLM invocado {actual_calls} veces pero el máximo era {expected_max} "
        f"(candidatos={n_candidates})"
    )
    assert actual_calls == expected_max, (
        f"LLM invocado {actual_calls} veces pero se esperaban {expected_max}"
    )
