"""Tests unitarios para CVELookUpAdapter.

Casos a cubrir (Tarea 3.3):
  1. error_lookup — el servidor MCP retorna un ErrorFinding tipo error_lookup
     (simula reintentos agotados del lado servidor).
  2. limit_exceeded — se pasan más de 50 dependencias, el adaptador solo
     procesa las primeras 50 y emite un ErrorFinding tipo limit_exceeded.
  3. error_input — version vacía, el servidor retorna ErrorFinding tipo error_input.
  4. Lista vacía — OSV no retorna vulnerabilidades, el adaptador retorna [].
"""

import json
from dataclasses import dataclass
from unittest.mock import AsyncMock

import pytest

from security_pr_guardian.adapters.mcp.cve_lookup_adapter import CVELookUpAdapter
from security_pr_guardian.core.models import (
    CVEFinding,
    DependencyChange,
    ErrorFinding,
)


# ---------------------------------------------------------------------------
# Helpers para simular respuestas MCP
# ---------------------------------------------------------------------------


@dataclass
class FakeMCPContent:
    """Simula un bloque de contenido retornado por el servidor MCP."""
    text: str


@dataclass
class FakeMCPResponse:
    """Simula la respuesta completa de `mcp_session.call_tool()`."""
    content: list[FakeMCPContent]


def make_mcp_response(data) -> FakeMCPResponse:
    """Crea un FakeMCPResponse a partir de un dict o lista serializable a JSON."""
    return FakeMCPResponse(content=[FakeMCPContent(text=json.dumps(data))])


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mcp_session():
    """Mock de la sesión MCP con call_tool como AsyncMock."""
    session = AsyncMock()
    return session


@pytest.fixture
def single_dependency() -> list[DependencyChange]:
    """Una sola dependencia de ejemplo."""
    return [
        DependencyChange(
            manifest_file="requirements.txt",
            package="requests",
            version="2.28.0",
            ecosystem="PyPI",
        )
    ]


@pytest.fixture
def many_dependencies() -> list[DependencyChange]:
    """55 dependencias — supera el límite de 50."""
    return [
        DependencyChange(
            manifest_file="requirements.txt",
            package=f"pkg-{i}",
            version=f"1.0.{i}",
            ecosystem="PyPI",
        )
        for i in range(55)
    ]


# ---------------------------------------------------------------------------
# Test 1: error_lookup — servidor reporta fallo tras reintentos agotados
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_error_lookup_returned_by_server(mcp_session, single_dependency):
    """
    DADO: el servidor MCP retorna un ErrorFinding de tipo 'error_lookup'
          (esto ocurre cuando OSV.dev falló tras reintentos).
    CUANDO: el adaptador llama a lookup_vulnerabilities con 1 dependencia.
    ENTONCES: el resultado contiene un ErrorFinding con tipo='error_lookup'.

    Pistas:
      - Configura mcp_session.call_tool.return_value con make_mcp_response(...)
      - El payload debe ser un dict con los campos de ErrorFinding
      - Verifica que results[0] es instancia de ErrorFinding y tipo == "error_lookup"
    """
    mcp_adapter = CVELookUpAdapter(mcp_session)
    mcp_session.call_tool.return_value = make_mcp_response({
        "tipo": "error_lookup",
        "paquete": "requests",
        "version": "2.28.0",
        "ecosistema": "",
        "error_descripcion": "Server error after retries"
    })

    results = await mcp_adapter.lookup_vulnerabilities(single_dependency)
    assert isinstance (results[0], ErrorFinding)
    assert results[0].tipo == "error_lookup"
    

# ---------------------------------------------------------------------------
# Test 2: limit_exceeded — más de 50 dependencias
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_limit_exceeded_when_over_50_dependencies(mcp_session, many_dependencies):
    """
    DADO: 55 dependencias en la lista de entrada.
    CUANDO: el adaptador llama a lookup_vulnerabilities.
    ENTONCES:
      - Se llama a call_tool exactamente 50 veces (no 55).
      - El último elemento del resultado es un ErrorFinding tipo 'limit_exceeded'.
      - La error_descripcion menciona que se omitieron 5 dependencias.

    Pistas:
      - Configura mcp_session.call_tool.return_value para retornar lista vacía []
      - Usa mcp_session.call_tool.call_count para verificar las 50 llamadas
      - El finding limit_exceeded se agrega AL FINAL de results
    """
    # TODO: Tu código aquí
    adapter = CVELookUpAdapter(mcp_session)
    mcp_session.call_tool.return_value = make_mcp_response([])

    results = await adapter.lookup_vulnerabilities(many_dependencies)

    assert mcp_session.call_tool.call_count == 50
    assert results[-1].tipo == "limit_exceeded"

# ---------------------------------------------------------------------------
# Test 3: error_input — version vacía
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_error_input_when_version_empty(mcp_session):
    """
    DADO: una dependencia con version="" (vacía).
    CUANDO: el adaptador llama a lookup_vulnerabilities.
    ENTONCES: el servidor MCP retorna un ErrorFinding con tipo='error_input'.

    Pistas:
      - El adaptador NO valida la versión, eso lo hace el SERVIDOR MCP.
      - Configura mcp_session.call_tool.return_value con un ErrorFinding de
        tipo 'error_input' (simulando lo que haría el servidor).
      - Verifica que results[0].tipo == "error_input"
    """
    dependency_empty_version = [
        DependencyChange(
            manifest_file="requirements.txt",
            package="requests",
            version="",
            ecosystem="PyPI",
        )
    ]

    mcp_adapter = CVELookUpAdapter(mcp_session)
    mcp_session.call_tool.return_value = make_mcp_response({
        "tipo": "error_input",
        "paquete": "requests",
        "version": "",
        "ecosistema": "PyPI",
        "error_descripcion": "Invalid version format"
    })

    results = await mcp_adapter.lookup_vulnerabilities(dependency_empty_version)
    assert results[0].tipo == "error_input"

# ---------------------------------------------------------------------------
# Test 4: lista vacía — OSV no retorna vulnerabilidades
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_empty_list_when_no_vulnerabilities(mcp_session, single_dependency):
    """
    DADO: el servidor MCP retorna una lista vacía [] (sin vulns).
    CUANDO: el adaptador llama a lookup_vulnerabilities con 1 dependencia.
    ENTONCES: el resultado es una lista vacía [].

    Pistas:
      - make_mcp_response([]) simula que OSV no encontró nada
      - La lista retornada debe tener len == 0
    """
    # TODO: Tu código aquí
    adapter = CVELookUpAdapter(mcp_session)
    mcp_session.call_tool.return_value = make_mcp_response([])
    results = await adapter.lookup_vulnerabilities(single_dependency)

    assert len(results) == 0