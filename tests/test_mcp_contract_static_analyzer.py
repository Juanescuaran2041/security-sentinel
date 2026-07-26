"""Test de contrato MCP para analyze_diff.

Verifica que la tool `analyze_diff` expuesta por el servidor MCP
static_analyzer_server retorna un resultado que coincide con el schema
JSON de StaticAnalysisResult (campos requeridos, tipos, y valores
esperados de `source`).
"""

from __future__ import annotations

import sys
from types import ModuleType
from unittest.mock import MagicMock

import pytest

# Stub del módulo mcp.server.fastmcp para evitar ImportError
# (la versión instalada de mcp no incluye FastMCP)
_fastmcp_stub = ModuleType("mcp.server.fastmcp")


class _FakeMCP:
    """Fake FastMCP que expone un decorador .tool() no-op."""

    def __init__(self, *args, **kwargs):
        pass

    def tool(self):
        def decorator(fn):
            return fn
        return decorator

    def run(self):
        pass


_fastmcp_stub.FastMCP = _FakeMCP  # type: ignore[attr-defined]
sys.modules.setdefault("mcp", MagicMock())
sys.modules.setdefault("mcp.server", MagicMock())
sys.modules.setdefault("mcp.server.fastmcp", _fastmcp_stub)

from security_pr_guardian.adapters.mcp.static_analyzer_server import analyze_diff  # noqa: E402
from security_pr_guardian.core.models import CandidateFinding, StaticAnalysisResult  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SQL_INJECTION_DIFF = """\
diff --git a/app/db.py b/app/db.py
--- a/app/db.py
+++ b/app/db.py
@@ -1,5 +1,10 @@
 import sqlite3

+def get_user(name: str):
+    conn = sqlite3.connect("app.db")
+    query = f"SELECT * FROM users WHERE username = '{name}'"
+    return conn.execute(query).fetchone()
+
 def get_all():
     conn = sqlite3.connect("app.db")
     return conn.execute("SELECT * FROM users").fetchall()
"""

EMPTY_DIFF = ""

CLEAN_DIFF = """\
diff --git a/app/utils.py b/app/utils.py
--- a/app/utils.py
+++ b/app/utils.py
@@ -1,3 +1,6 @@
 import logging

+def get_logger(name: str) -> logging.Logger:
+    return logging.getLogger(name)
+
 logger = logging.getLogger(__name__)
"""

# Campos requeridos en cada CandidateFinding
REQUIRED_FINDING_FIELDS = {
    "finding_id",
    "source",
    "tipo_vulnerabilidad",
    "archivo",
    "linea_inicio",
    "linea_fin",
    "fragmento_codigo",
    "patron_detectado",
    "severidad_inicial",
}

# Campos opcionales que pueden estar presentes
OPTIONAL_FINDING_FIELDS = {
    "cwe_id",
    "cve_id",
    "paquete",
    "version",
    "ecosistema",
}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_analyze_diff_with_sql_injection_returns_valid_schema():
    """Un diff con SQL injection produce findings que cumplen el schema."""
    result = await analyze_diff(SQL_INJECTION_DIFF)

    # El resultado debe ser una instancia de StaticAnalysisResult
    assert isinstance(result, StaticAnalysisResult)

    # Campos de nivel superior
    assert hasattr(result, "findings")
    assert hasattr(result, "errores_parciales")
    assert isinstance(result.findings, list)
    assert isinstance(result.errores_parciales, list)

    # Debe tener al menos un finding
    assert len(result.findings) > 0

    # Validar schema de cada finding
    for finding in result.findings:
        assert isinstance(finding, CandidateFinding)
        finding_dict = finding.model_dump()

        # Todos los campos requeridos están presentes
        for field_name in REQUIRED_FINDING_FIELDS:
            assert field_name in finding_dict, (
                f"Campo requerido '{field_name}' falta en finding"
            )

        # source siempre es "static" para el analizador estático
        assert finding.source == "static"

        # Tipos correctos
        assert isinstance(finding.finding_id, str)
        assert len(finding.finding_id) > 0
        assert isinstance(finding.tipo_vulnerabilidad, str)
        assert isinstance(finding.archivo, str)
        assert isinstance(finding.linea_inicio, int)
        assert isinstance(finding.linea_fin, int)
        assert isinstance(finding.fragmento_codigo, str)
        assert isinstance(finding.patron_detectado, str)
        assert finding.severidad_inicial is not None


@pytest.mark.asyncio
async def test_analyze_diff_with_empty_diff_returns_empty_findings():
    """Un diff vacío produce una lista vacía de findings."""
    result = await analyze_diff(EMPTY_DIFF)

    assert isinstance(result, StaticAnalysisResult)
    assert isinstance(result.findings, list)
    assert isinstance(result.errores_parciales, list)
    assert len(result.findings) == 0


@pytest.mark.asyncio
async def test_analyze_diff_with_clean_diff_returns_empty_findings():
    """Un diff limpio (sin vulnerabilidades) produce findings vacíos."""
    result = await analyze_diff(CLEAN_DIFF)

    assert isinstance(result, StaticAnalysisResult)
    assert isinstance(result.findings, list)
    assert isinstance(result.errores_parciales, list)
    assert len(result.findings) == 0


@pytest.mark.asyncio
async def test_analyze_diff_output_matches_json_schema():
    """El output serializado a JSON coincide con el schema de StaticAnalysisResult."""
    result = await analyze_diff(SQL_INJECTION_DIFF)

    # Serializar y validar round-trip via pydantic
    result_dict = result.model_dump()

    # Validar estructura de nivel superior
    assert "findings" in result_dict
    assert "errores_parciales" in result_dict

    # Reconstruir desde dict debe funcionar sin errores
    reconstructed = StaticAnalysisResult.model_validate(result_dict)
    assert len(reconstructed.findings) == len(result.findings)
    assert len(reconstructed.errores_parciales) == len(result.errores_parciales)


@pytest.mark.asyncio
async def test_analyze_diff_finding_optional_fields_are_valid():
    """Los campos opcionales en findings tienen tipos correctos si están presentes."""
    result = await analyze_diff(SQL_INJECTION_DIFF)

    for finding in result.findings:
        finding_dict = finding.model_dump()

        # Campos opcionales pueden ser None o del tipo correcto
        if finding_dict.get("cwe_id") is not None:
            assert isinstance(finding.cwe_id, str)
        if finding_dict.get("cve_id") is not None:
            assert isinstance(finding.cve_id, str)
        if finding_dict.get("paquete") is not None:
            assert isinstance(finding.paquete, str)
        if finding_dict.get("version") is not None:
            assert isinstance(finding.version, str)
        if finding_dict.get("ecosistema") is not None:
            assert isinstance(finding.ecosistema, str)
