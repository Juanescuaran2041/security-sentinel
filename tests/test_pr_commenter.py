"""Tests unitarios para GitHubPRCommenterAdapter (Tarea 7.3).

Casos a cubrir:
  1. POST en primer comentario (ningún comentario previo con watermark).
  2. PATCH en comentario subsiguiente (watermark detectado en comentario existente).
  3. Reintento en error 5xx (mockeado con pytest-httpx).
  4. Evento `comment_publish_failed` emitido tras reintentos agotados.

Estrategia de mocking:
  - pytest-httpx para simular respuestas de la API de GitHub.
  - AnalysisResult con datos mínimos suficientes para renderizar la plantilla.
  - StructuredLogger mockeado para capturar eventos emitidos.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
import pytest_asyncio
from pytest_httpx import HTTPXMock

from security_pr_guardian.adapters.github.pr_commenter import (
    WATERMARK,
    GitHubPRCommenterAdapter,
)
from security_pr_guardian.core.models import (
    AnalysisResult,
    ConfirmedFinding,
    Recommendation,
    Severity,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

REPO = "owner/repo"
PR_NUMBER = 42
COMMENT_ID = 99999


def make_confirmed_finding(
    severity: Severity = Severity.HIGH,
    disposition: str = "incluido",
) -> ConfirmedFinding:
    """Crea un ConfirmedFinding mínimo para usar en los tests."""
    return ConfirmedFinding(
        finding_id="test-finding-id",
        source="static",
        tipo_vulnerabilidad="SQL Injection",
        archivo="app/db.py",
        linea_inicio=10,
        linea_fin=10,
        fragmento_codigo='query = "SELECT * FROM users WHERE id = %s" % uid',
        cwe_id="CWE-89",
        severidad_ajustada=severity,
        justificacion="Este hallazgo es explotable porque el input del usuario llega sin sanitizar directamente a la query SQL construida por concatenación de strings.",
        recomendacion=Recommendation(
            descripcion="Usar consultas parametrizadas.",
            codigo_corregido='cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))',
            referencia="CWE-89",
        ),
        disposition=disposition,
    )


@pytest.fixture
def mock_logger() -> MagicMock:
    """Logger mockeado para capturar eventos."""
    return MagicMock()


@pytest.fixture
def analysis_result() -> AnalysisResult:
    """AnalysisResult mínimo con un finding confirmado."""
    return AnalysisResult(
        repo=REPO,
        pr_number=PR_NUMBER,
        candidate_count=3,
        confirmed_count=1,
        discarded_count=2,
        not_evaluated_count=0,
        confirmed_findings=[make_confirmed_finding()],
        diff_truncated=False,
        dependency_limit_exceeded=False,
        duration_seconds=5.2,
        model_id="anthropic.claude-3-sonnet",
        guardian_version="0.1.0",
        timestamp_utc=datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
    )


@pytest.fixture
def adapter(mock_logger, analysis_result) -> GitHubPRCommenterAdapter:
    """Adaptador listo para usar en los tests."""
    return GitHubPRCommenterAdapter(
        token="ghp_test_token",
        logger=mock_logger,
        analysis_result=analysis_result,
        base_url="https://api.github.com",
    )


# ---------------------------------------------------------------------------
# Test 1: POST en primer comentario (sin comentario previo)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_creates_new_comment_when_none_exists(
    adapter: GitHubPRCommenterAdapter,
    httpx_mock: HTTPXMock,
):
    """
    DADO: No existe ningún comentario previo en el PR (lista vacía).
    CUANDO: se llama a post_or_update_comment().
    ENTONCES: se hace un POST y se retorna el comment_id creado.
    """
    httpx_mock.add_response(
        method="GET",
        url="https://api.github.com/repos/owner/repo/issues/42/comments",
        status_code=200,
        json=[],
    )
    httpx_mock.add_response(
        method="POST",
        url="https://api.github.com/repos/owner/repo/issues/42/comments",
        status_code=201,
        json={"id": COMMENT_ID, "body": "<!-- security-pr-guardian --> new comment"},
    )

    result = await adapter.post_or_update_comment(REPO, PR_NUMBER, findings=[])

    assert result == str(COMMENT_ID)


# ---------------------------------------------------------------------------
# Test 2: PATCH cuando ya existe comentario con watermark
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_updates_existing_comment_when_watermark_found(
    adapter: GitHubPRCommenterAdapter,
    httpx_mock: HTTPXMock,
):
    """
    DADO: Ya existe un comentario en el PR que contiene la marca de agua.
    CUANDO: se llama a post_or_update_comment().
    ENTONCES: se hace un PATCH (no POST) y se retorna el mismo comment_id.
    """
    httpx_mock.add_response(
        method="GET",
        url="https://api.github.com/repos/owner/repo/issues/42/comments",
        status_code=200,
        json=[{"id": COMMENT_ID, "body": f"{WATERMARK} old content"}],
    )
    httpx_mock.add_response(
        method="PATCH",
        url=f"https://api.github.com/repos/owner/repo/issues/comments/{COMMENT_ID}",
        status_code=200,
        json={"id": COMMENT_ID, "body": "updated content"},
    )

    result = await adapter.post_or_update_comment(REPO, PR_NUMBER, findings=[])

    assert result == str(COMMENT_ID)


# ---------------------------------------------------------------------------
# Test 3: Reintento en error 5xx
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_retries_on_5xx_error(
    adapter: GitHubPRCommenterAdapter,
    httpx_mock: HTTPXMock,
):
    """
    DADO: El POST falla con 500 las primeras 2 veces y tiene éxito a la 3ra.
    CUANDO: se llama a post_or_update_comment().
    ENTONCES: el adaptador reintenta y retorna el comment_id en el 3er intento.
    """
    from unittest.mock import AsyncMock, patch

    httpx_mock.add_response(
        method="GET",
        url="https://api.github.com/repos/owner/repo/issues/42/comments",
        status_code=200,
        json=[],
    )
    # First two POSTs fail with 500, third succeeds
    httpx_mock.add_response(
        method="POST",
        url="https://api.github.com/repos/owner/repo/issues/42/comments",
        status_code=500,
    )
    httpx_mock.add_response(
        method="POST",
        url="https://api.github.com/repos/owner/repo/issues/42/comments",
        status_code=500,
    )
    httpx_mock.add_response(
        method="POST",
        url="https://api.github.com/repos/owner/repo/issues/42/comments",
        status_code=201,
        json={"id": COMMENT_ID, "body": "<!-- security-pr-guardian --> comment"},
    )

    with patch(
        "security_pr_guardian.adapters.github.pr_commenter.asyncio.sleep",
        new_callable=AsyncMock,
    ):
        result = await adapter.post_or_update_comment(REPO, PR_NUMBER, findings=[])

    assert result == str(COMMENT_ID)


# ---------------------------------------------------------------------------
# Test 4: comment_publish_failed tras reintentos agotados
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_emits_comment_publish_failed_after_exhausted_retries(
    adapter: GitHubPRCommenterAdapter,
    mock_logger: MagicMock,
    httpx_mock: HTTPXMock,
):
    """
    DADO: El POST falla con 500 en los 3 intentos.
    CUANDO: se llama a post_or_update_comment().
    ENTONCES:
      - Se lanza RuntimeError.
      - El logger emite un evento con evento="comment_publish_failed".
    """
    from unittest.mock import AsyncMock, patch

    httpx_mock.add_response(
        method="GET",
        url="https://api.github.com/repos/owner/repo/issues/42/comments",
        status_code=200,
        json=[],
    )
    for _ in range(3):
        httpx_mock.add_response(
            method="POST",
            url="https://api.github.com/repos/owner/repo/issues/42/comments",
            status_code=500,
        )

    with patch(
        "security_pr_guardian.adapters.github.pr_commenter.asyncio.sleep",
        new_callable=AsyncMock,
    ):
        with pytest.raises(RuntimeError):
            await adapter.post_or_update_comment(REPO, PR_NUMBER, findings=[])

    calls = mock_logger.log.call_args_list
    assert any(
        call.kwargs.get("evento") == "comment_publish_failed"
        for call in calls
    )
