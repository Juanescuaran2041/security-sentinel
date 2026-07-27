"""Tests unitarios del SecurityAgent (Tarea 8.1 / 8.2).

Cubre:
  - CVE analysis omitido cuando no hay manifiestos en el diff
  - Cap de 20 findings respetado (> 20 candidatos → solo 20 al LLM)
  - no_evaluado propagado cuando el LLM lanza excepción
  - disposition: "descartado" para findings con es_explotable=False
  - dry-run (--no-comment) omite PRCommentPort
  - analysis_id es un UUID v4 válido en el resultado
  - Findings en resultado ordenados por severidad descendente

Estrategia:
  - Todos los puertos se mockean con unittest.mock.AsyncMock.
  - Ningún test llama a infraestructura real.
"""

from __future__ import annotations

import io
import json
import re
import uuid
from typing import Any
from unittest.mock import AsyncMock

import pytest

from security_pr_guardian.core.agent import MAX_FINDINGS_LLM, SecurityAgent
from security_pr_guardian.core.logger import StructuredLogger
from security_pr_guardian.core.models import (
    AppConfig,
    CandidateFinding,
    CVEFinding,
    KBFragment,
    LLMVerdict,
    Recommendation,
    Severity,
    SEVERITY_ORDER,
    StaticAnalysisResult,
)

# ---------------------------------------------------------------------------
# Constants
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


# ---------------------------------------------------------------------------
# Helpers / Factories
# ---------------------------------------------------------------------------


def make_config(**overrides) -> AppConfig:
    """Crea un AppConfig válido para tests."""
    defaults = {
        "github_token": "ghp_test",
        "llm_backend": "bedrock",
        "bedrock_region": "us-east-1",
        "bedrock_model_id": "anthropic.claude-3-sonnet-20240229-v1:0",
    }
    defaults.update(overrides)
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


def make_verdict(
    explotable: bool = True, severity: Severity = Severity.HIGH
) -> LLMVerdict:
    """Crea un LLMVerdict para tests."""
    return LLMVerdict(
        es_explotable=explotable,
        severidad_ajustada=severity,
        justificacion=(
            "El input del usuario llega sin sanitizar directamente a la "
            "consulta SQL, permitiendo inyección arbitraria de comandos SQL "
            "que comprometen la integridad de la base de datos."
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
) -> SecurityAgent:
    """Construye un SecurityAgent con todos los puertos mockeados."""
    if sast_findings is None:
        sast_findings = []
    if cve_findings is None:
        cve_findings = []

    config = make_config()
    output = log_output or io.StringIO()
    logger = StructuredLogger(str(uuid.uuid4()), output=output)

    diff_port = AsyncMock()
    diff_port.get_diff.return_value = diff

    static_port = AsyncMock()
    static_port.analyze_diff.return_value = StaticAnalysisResult(
        findings=sast_findings
    )

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
    return agent


# ---------------------------------------------------------------------------
# Test: CVE analysis omitido cuando no hay manifiestos
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cve_skipped_when_no_manifests():
    """
    DADO: Un diff sin manifiestos de dependencias.
    CUANDO: se ejecuta run().
    ENTONCES: lookup_vulnerabilities NO se llama.
    """
    agent = build_agent(diff=DIFF_NO_MANIFEST)
    await agent.run(repo="owner/repo", pr_number=1)

    agent.cve_lookup_port.lookup_vulnerabilities.assert_not_called()


@pytest.mark.asyncio
async def test_cve_called_when_manifests_present():
    """
    DADO: Un diff con requirements.txt modificado.
    CUANDO: se ejecuta run().
    ENTONCES: lookup_vulnerabilities SÍ se llama.
    """
    agent = build_agent(diff=DIFF_WITH_MANIFEST)
    await agent.run(repo="owner/repo", pr_number=1)

    agent.cve_lookup_port.lookup_vulnerabilities.assert_called_once()


# ---------------------------------------------------------------------------
# Test: Cap de 20 findings respetado
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_llm_cap_of_20_findings():
    """
    DADO: 25 CandidateFindings de SAST.
    CUANDO: se ejecuta run().
    ENTONCES: evaluate_finding se llama exactamente 20 veces (tope).
    """
    candidates = [make_candidate() for _ in range(25)]
    agent = build_agent(sast_findings=candidates)
    await agent.run(repo="owner/repo", pr_number=1)

    assert agent.llm_reasoning_port.evaluate_finding.call_count == MAX_FINDINGS_LLM


@pytest.mark.asyncio
async def test_llm_cap_less_than_20():
    """
    DADO: 5 CandidateFindings.
    CUANDO: se ejecuta run().
    ENTONCES: evaluate_finding se llama exactamente 5 veces (todos evaluados).
    """
    candidates = [make_candidate() for _ in range(5)]
    agent = build_agent(sast_findings=candidates)
    await agent.run(repo="owner/repo", pr_number=1)

    assert agent.llm_reasoning_port.evaluate_finding.call_count == 5


# ---------------------------------------------------------------------------
# Test: no_evaluado cuando el LLM lanza excepción
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_no_evaluado_when_llm_raises():
    """
    DADO: El LLM lanza excepción en todos los findings.
    CUANDO: se ejecuta run().
    ENTONCES: todos los ConfirmedFindings tienen disposition='no_evaluado'.
    """
    candidates = [make_candidate(), make_candidate()]
    agent = build_agent(
        sast_findings=candidates,
        llm_side_effect=RuntimeError("Bedrock timeout"),
    )
    result = await agent.run(repo="owner/repo", pr_number=1)

    assert all(f.disposition == "no_evaluado" for f in result.confirmed_findings)
    assert result.not_evaluated_count == 2


# ---------------------------------------------------------------------------
# Test: disposition "descartado" para no explotables
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_discarded_for_non_exploitable():
    """
    DADO: El LLM retorna es_explotable=False para todos los findings.
    CUANDO: se ejecuta run().
    ENTONCES: disposition='descartado' en todos los ConfirmedFindings.
    """
    candidates = [make_candidate(), make_candidate()]
    agent = build_agent(sast_findings=candidates)
    agent.llm_reasoning_port.evaluate_finding.return_value = make_verdict(
        explotable=False
    )
    result = await agent.run(repo="owner/repo", pr_number=1)

    assert all(f.disposition == "descartado" for f in result.confirmed_findings)
    assert result.discarded_count == 2
    assert result.confirmed_count == 0


# ---------------------------------------------------------------------------
# Test: dry-run (--no-comment) omite PRCommentPort
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dry_run_omits_comment_port():
    """
    DADO: dry_run=True.
    CUANDO: se ejecuta run().
    ENTONCES: post_or_update_comment NO se llama y comment_id es None.
    """
    agent = build_agent(sast_findings=[make_candidate()])
    result = await agent.run(repo="owner/repo", pr_number=1, dry_run=True)

    agent.pr_comment_port.post_or_update_comment.assert_not_called()
    assert result.comment_id is None


@pytest.mark.asyncio
async def test_dry_run_false_calls_comment_port():
    """
    DADO: dry_run=False (default).
    CUANDO: se ejecuta run().
    ENTONCES: post_or_update_comment SÍ se llama y comment_id aparece en el resultado.
    """
    agent = build_agent(sast_findings=[make_candidate()], comment_id="456")
    result = await agent.run(repo="owner/repo", pr_number=1, dry_run=False)

    agent.pr_comment_port.post_or_update_comment.assert_called_once()
    assert result.comment_id == "456"


# ---------------------------------------------------------------------------
# Test: analysis_id es UUID v4 válido
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_analysis_id_is_valid_uuid_v4():
    """
    DADO: Ejecución normal del agente.
    CUANDO: se ejecuta run().
    ENTONCES: el analysis_id en el resultado es UUID v4 válido.
    """
    agent = build_agent(sast_findings=[make_candidate()])
    result = await agent.run(repo="owner/repo", pr_number=1, dry_run=True)

    assert UUID_V4_RE.match(result.analysis_id), (
        f"analysis_id no es UUID v4: {result.analysis_id}"
    )
    # Also verify it's a valid UUID object
    parsed = uuid.UUID(result.analysis_id, version=4)
    assert str(parsed) == result.analysis_id


@pytest.mark.asyncio
async def test_analysis_id_in_log_events():
    """
    DADO: Ejecución con captura de logs.
    CUANDO: se ejecuta run().
    ENTONCES: todos los eventos de log contienen analysis_id UUID v4.
    """
    log_output = io.StringIO()
    agent = build_agent(sast_findings=[make_candidate()], log_output=log_output)
    result = await agent.run(repo="owner/repo", pr_number=1, dry_run=True)

    log_output.seek(0)
    lines = [l for l in log_output.read().splitlines() if l.strip()]
    assert len(lines) > 0, "No se emitieron eventos de log"

    for line in lines:
        event = json.loads(line)
        assert "analysis_id" in event
        assert UUID_V4_RE.match(event["analysis_id"]), (
            f"analysis_id no es UUID v4: {event['analysis_id']}"
        )
        # All events in this run should share the same analysis_id
        assert event["analysis_id"] == result.analysis_id


# ---------------------------------------------------------------------------
# Test: Findings en resultado ordenados por severidad descendente
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_findings_sorted_by_severity_descending():
    """
    DADO: Candidatos con severidades variadas.
    CUANDO: se ejecuta run().
    ENTONCES: confirmed_findings están ordenados por severidad descendente.
    """
    severities = [Severity.LOW, Severity.CRITICAL, Severity.MEDIUM, Severity.HIGH]
    candidates = [make_candidate(severity=s) for s in severities]
    verdicts = [make_verdict(explotable=True, severity=s) for s in severities]

    agent = build_agent(sast_findings=candidates)
    agent.llm_reasoning_port.evaluate_finding.side_effect = verdicts

    result = await agent.run(repo="owner/repo", pr_number=1, dry_run=True)

    # Verify descending order
    for i in range(len(result.confirmed_findings) - 1):
        current = SEVERITY_ORDER[result.confirmed_findings[i].severidad_ajustada]
        next_one = SEVERITY_ORDER[result.confirmed_findings[i + 1].severidad_ajustada]
        assert current >= next_one, (
            f"Inversión de severidad en posición {i}: "
            f"{result.confirmed_findings[i].severidad_ajustada} < "
            f"{result.confirmed_findings[i+1].severidad_ajustada}"
        )


@pytest.mark.asyncio
async def test_candidates_sorted_before_llm_cap():
    """
    DADO: 25 candidatos con severidades variadas (algunos CRITICAL, algunos INFO).
    CUANDO: se ejecuta run() con tope de 20.
    ENTONCES: Los candidatos que llegan al LLM son los de mayor severidad.
    """
    # 10 CRITICAL + 15 INFO = 25 total, only 20 should go to LLM
    candidates = [make_candidate(severity=Severity.CRITICAL) for _ in range(10)] + [
        make_candidate(severity=Severity.INFO) for _ in range(15)
    ]

    # Make LLM return a verdict that preserves the candidate's severity
    async def preserve_severity(finding, kb_context):
        return make_verdict(explotable=True, severity=finding.severidad_inicial)

    agent = build_agent(sast_findings=candidates)
    agent.llm_reasoning_port.evaluate_finding.side_effect = preserve_severity
    result = await agent.run(repo="owner/repo", pr_number=1, dry_run=True)

    # All 10 CRITICAL should be in the result (within top 20)
    critical_findings = [
        f
        for f in result.confirmed_findings
        if f.severidad_ajustada == Severity.CRITICAL
    ]
    assert len(critical_findings) == 10

    # Only 10 of the 15 INFO should make it (20 - 10 = 10)
    info_findings = [
        f for f in result.confirmed_findings if f.severidad_ajustada == Severity.INFO
    ]
    assert len(info_findings) == 10

    # Total evaluated should be 20
    assert agent.llm_reasoning_port.evaluate_finding.call_count == MAX_FINDINGS_LLM


# ---------------------------------------------------------------------------
# Test: Structured log events emitted at each stage
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_structured_log_events_emitted():
    """
    DADO: Ejecución completa del agente.
    CUANDO: se ejecuta run().
    ENTONCES: Se emiten eventos de log en las etapas clave del pipeline.
    """
    log_output = io.StringIO()
    agent = build_agent(
        diff=DIFF_WITH_MANIFEST,
        sast_findings=[make_candidate()],
        log_output=log_output,
    )
    await agent.run(repo="owner/repo", pr_number=1, dry_run=True)

    log_output.seek(0)
    events = [json.loads(l) for l in log_output.read().splitlines() if l.strip()]

    event_names = [e["detalle"].get("") if "evento" not in e else e["evento"]
                   for e in events]
    # Actually extract properly
    event_names = [e["evento"] for e in events]

    assert "analysis_started" in event_names
    assert "diff_fetch_complete" in event_names
    assert "static_analysis_complete" in event_names
    assert "analysis_complete" in event_names


@pytest.mark.asyncio
async def test_comment_port_receives_analysis_result():
    """
    DADO: Ejecución normal sin dry_run.
    CUANDO: se ejecuta run().
    ENTONCES: post_or_update_comment recibe (repo, pr_number, AnalysisResult).
    """
    agent = build_agent(sast_findings=[make_candidate()])
    await agent.run(repo="owner/repo", pr_number=1, dry_run=False)

    call_args = agent.pr_comment_port.post_or_update_comment.call_args
    assert call_args[0][0] == "owner/repo"
    assert call_args[0][1] == 1
    # Third argument should be an AnalysisResult
    from security_pr_guardian.core.models import AnalysisResult

    assert isinstance(call_args[0][2], AnalysisResult)


# ---------------------------------------------------------------------------
# Property-Based Test: Los hallazgos no explotables siempre se descartan
# ---------------------------------------------------------------------------

import asyncio

from hypothesis import given, settings
from hypothesis import strategies as st


# Strategy: genera CandidateFinding válidos para Hypothesis
candidate_finding_strategy = st.builds(
    CandidateFinding,
    source=st.sampled_from(["static", "cve"]),
    tipo_vulnerabilidad=st.text(min_size=1, max_size=30),
    archivo=st.text(min_size=1, max_size=50).filter(lambda s: s.strip() != ""),
    linea_inicio=st.integers(min_value=0, max_value=10000),
    linea_fin=st.integers(min_value=0, max_value=10000),
    fragmento_codigo=st.text(min_size=1, max_size=499),
    patron_detectado=st.text(min_size=1, max_size=50),
    cwe_id=st.one_of(st.none(), st.from_regex(r"CWE-\d{1,4}", fullmatch=True)),
    cve_id=st.one_of(st.none(), st.from_regex(r"CVE-\d{4}-\d{4,}", fullmatch=True)),
    severidad_inicial=st.sampled_from(list(Severity)),
)


@settings(max_examples=100)
@given(candidates=st.lists(candidate_finding_strategy, min_size=0, max_size=30))
def test_property_non_exploitable_findings_always_discarded(candidates):
    """
    **Validates: Requirements 5.5**

    Property 1: Los hallazgos no explotables siempre se descartan.

    Para cualquier conjunto de hallazgos candidatos evaluados por el LLM,
    todo hallazgo donde es_explotable sea false debe tener
    disposition: "descartado" y no debe aparecer en el subconjunto de
    findings con disposition "incluido" (confirmed_findings filtrado).
    """
    # Mock the LLM to ALWAYS return es_explotable=False
    verdict_non_exploitable = make_verdict(explotable=False, severity=Severity.MEDIUM)

    # Build agent with all ports mocked — use return_value directly
    # instead of side_effect to avoid async/sync issues with Hypothesis
    config = make_config()
    log_output = io.StringIO()
    logger = StructuredLogger(str(uuid.uuid4()), output=log_output)

    diff_port = AsyncMock()
    diff_port.get_diff.return_value = DIFF_NO_MANIFEST

    static_port = AsyncMock()
    static_port.analyze_diff.return_value = StaticAnalysisResult(
        findings=candidates
    )

    cve_port = AsyncMock()
    cve_port.lookup_vulnerabilities.return_value = []

    kb_port = AsyncMock()
    kb_port.retrieve.return_value = [make_kb_fragment()]

    llm_port = AsyncMock()
    llm_port.evaluate_finding.return_value = verdict_non_exploitable

    comment_port = AsyncMock()
    comment_port.post_or_update_comment.return_value = "123"

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

    # Run the async agent synchronously for Hypothesis compatibility
    loop = asyncio.new_event_loop()
    try:
        result = loop.run_until_complete(
            agent.run(repo="owner/repo", pr_number=1, dry_run=True)
        )
    finally:
        loop.close()

    # Property assertion 1: ALL findings must have disposition "descartado"
    for finding in result.confirmed_findings:
        assert finding.disposition == "descartado", (
            f"Finding {finding.finding_id} tiene disposition='{finding.disposition}' "
            f"pero debería ser 'descartado' porque es_explotable=False"
        )

    # Property assertion 2: No "descartado" finding appears in the "incluido" subset
    incluidos = [f for f in result.confirmed_findings if f.disposition == "incluido"]
    descartados_ids = {
        f.finding_id for f in result.confirmed_findings if f.disposition == "descartado"
    }
    for f in incluidos:
        assert f.finding_id not in descartados_ids, (
            f"Finding {f.finding_id} aparece como 'incluido' pero fue marcado "
            f"como 'descartado'"
        )

    # Property assertion 3: confirmed_count must be 0 (no exploitable findings)
    assert result.confirmed_count == 0, (
        f"confirmed_count debería ser 0 pero es {result.confirmed_count}"
    )

    # Property assertion 4: discarded_count matches total evaluated findings
    expected_evaluated = min(len(candidates), MAX_FINDINGS_LLM)
    assert result.discarded_count == expected_evaluated, (
        f"discarded_count={result.discarded_count} pero se esperaba "
        f"{expected_evaluated} (min({len(candidates)}, {MAX_FINDINGS_LLM}))"
    )


# ---------------------------------------------------------------------------
# Property-Based Test: analysis_id es UUID v4 válido en todos los eventos de log
# ---------------------------------------------------------------------------


@settings(max_examples=100)
@given(
    num_candidates=st.integers(min_value=0, max_value=30),
    has_manifests=st.booleans(),
    osv_timeout=st.integers(min_value=1, max_value=300),
    max_diff_lines=st.integers(min_value=1, max_value=10000),
    max_dependencies=st.integers(min_value=1, max_value=1000),
)
def test_property_analysis_id_uuid_v4_in_all_log_events(
    num_candidates: int,
    has_manifests: bool,
    osv_timeout: int,
    max_diff_lines: int,
    max_dependencies: int,
):
    """
    **Validates: Requirements 9.1, 9.2**

    Property 2: analysis_id es UUID v4 válido en todos los eventos de log.

    Para cualquier configuración válida de AppConfig y cualquier número de
    candidatos (0 a 30), con o sin manifiestos en el diff:
    - Todos los eventos de log emitidos son JSON válido.
    - Cada evento contiene un campo `analysis_id`.
    - Cada `analysis_id` cumple el formato UUID v4.
    - Todos los eventos de una misma ejecución comparten el MISMO analysis_id.
    - El analysis_id del resultado coincide con el de los eventos de log.
    """
    # Build AppConfig with varied optional numeric fields
    config = AppConfig(
        _env_file=None,
        github_token="ghp_test_token",
        llm_backend="bedrock",
        bedrock_region="us-east-1",
        bedrock_model_id="anthropic.claude-3-sonnet-20240229-v1:0",
        osv_timeout_seconds=osv_timeout,
        max_diff_lines=max_diff_lines,
        max_dependencies=max_dependencies,
    )

    # Generate candidate findings
    candidates = [make_candidate(severity=Severity.MEDIUM) for _ in range(num_candidates)]

    # Choose diff based on whether manifests are present
    diff = DIFF_WITH_MANIFEST if has_manifests else DIFF_NO_MANIFEST

    # Set up log capture
    log_output = io.StringIO()
    logger = StructuredLogger(str(uuid.uuid4()), output=log_output)

    # Build all mocked ports
    diff_port = AsyncMock()
    diff_port.get_diff.return_value = diff

    static_port = AsyncMock()
    static_port.analyze_diff.return_value = StaticAnalysisResult(findings=candidates)

    cve_port = AsyncMock()
    cve_port.lookup_vulnerabilities.return_value = []

    kb_port = AsyncMock()
    kb_port.retrieve.return_value = [make_kb_fragment()]

    llm_port = AsyncMock()
    llm_port.evaluate_finding.return_value = make_verdict(explotable=True)

    comment_port = AsyncMock()
    comment_port.post_or_update_comment.return_value = "123"

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

    # Run the async agent synchronously for Hypothesis compatibility
    loop = asyncio.new_event_loop()
    try:
        result = loop.run_until_complete(
            agent.run(repo="owner/repo", pr_number=1, dry_run=True)
        )
    finally:
        loop.close()

    # Parse all log events
    log_output.seek(0)
    raw_lines = [line for line in log_output.read().splitlines() if line.strip()]

    # There should always be at least 1 log event (analysis_started + analysis_complete)
    assert len(raw_lines) >= 1, (
        f"Se esperaban al menos 1 evento de log, pero se obtuvieron {len(raw_lines)}"
    )

    # Property assertion 1: All log lines are valid JSON
    events = []
    for i, line in enumerate(raw_lines):
        try:
            event = json.loads(line)
            events.append(event)
        except json.JSONDecodeError as e:
            raise AssertionError(
                f"Línea de log {i} no es JSON válido: {line!r}\nError: {e}"
            )

    # Property assertion 2: Every event has 'analysis_id' key
    for i, event in enumerate(events):
        assert "analysis_id" in event, (
            f"Evento de log {i} no contiene 'analysis_id': {event}"
        )

    # Property assertion 3: Every analysis_id matches UUID v4 regex pattern
    for i, event in enumerate(events):
        aid = event["analysis_id"]
        assert UUID_V4_RE.match(aid), (
            f"Evento de log {i}: analysis_id '{aid}' no cumple formato UUID v4"
        )

    # Property assertion 4: All events in a single run share the SAME analysis_id
    unique_ids = set(event["analysis_id"] for event in events)
    assert len(unique_ids) == 1, (
        f"Se encontraron {len(unique_ids)} analysis_id distintos en una sola "
        f"ejecución: {unique_ids}. Todos deben ser iguales."
    )

    # Property assertion 5: The result's analysis_id matches the log events' analysis_id
    log_analysis_id = unique_ids.pop()
    assert result.analysis_id == log_analysis_id, (
        f"El analysis_id del resultado ({result.analysis_id}) no coincide con "
        f"el de los eventos de log ({log_analysis_id})"
    )
