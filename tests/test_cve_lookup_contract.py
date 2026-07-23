"""Test de contrato MCP para la tool `lookup_cve`.

Verifica que dado un input válido `{"package": str, "version": str, "ecosystem": str}`,
el output del servidor MCP coincide con el schema de `list[CVEFinding]` o `ErrorFinding`.

Se llama directamente a la función `lookup_cve` (sin levantar el servidor MCP completo)
y se mockea HTTP con `pytest-httpx` para simular las respuestas de OSV.dev.

Casos del contrato:
  1. Input válido + OSV retorna vulnerabilidades → lista de CVEFinding con schema correcto.
  2. Input válido + OSV retorna lista vacía → lista vacía [].
  3. Input con version vacía → ErrorFinding con tipo="error_input".
  4. OSV retorna error HTTP persistente → ErrorFinding con tipo="error_lookup".
"""

import pytest
from pytest_httpx import HTTPXMock

from security_pr_guardian.adapters.mcp.cve_lookup_server import lookup_cve
from security_pr_guardian.core.models import CVEFinding, ErrorFinding


# ---------------------------------------------------------------------------
# Constantes — URL que el servidor usa internamente
# ---------------------------------------------------------------------------

OSV_URL = "https://api.osv.dev/v1/querybatch"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Respuesta OSV simulada con 1 vulnerabilidad
OSV_RESPONSE_WITH_VULN = {
    "results": [
        {
            "vulns": [
                {
                    "id": "GHSA-xxxx-yyyy-zzzz",
                    "aliases": ["CVE-2023-12345"],
                    "summary": "Remote code execution in requests library",
                    "severity": [{"type": "CVSS_V3", "score": "9.1"}],
                    "references": [
                        {"type": "WEB", "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-12345"}
                    ],
                }
            ]
        }
    ]
}

# Respuesta OSV simulada sin vulnerabilidades
OSV_RESPONSE_EMPTY = {
    "results": [{"vulns": []}]
}


# ---------------------------------------------------------------------------
# Test 1: Contrato — input válido, OSV retorna vulnerabilidades
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_contract_lookup_cve_returns_cve_findings(httpx_mock: HTTPXMock):
    """
    DADO: OSV.dev retorna 1 vulnerabilidad para el paquete "requests" v2.28.0.
    CUANDO: se invoca lookup_cve("requests", "2.28.0", "PyPI").
    ENTONCES:
      - El resultado es una lista (no un ErrorFinding).
      - Cada elemento es un CVEFinding válido con los campos requeridos:
        cve_id, paquete, version, ecosistema, severidad, descripcion, referencias.
      - severidad es uno de: "CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE".
      - referencias es una lista de strings (URLs).

   """
    httpx_mock.add_response(url= OSV_URL, json=OSV_RESPONSE_WITH_VULN)
    result = await lookup_cve("requests", "2.28.8", "PyPI")
    assert isinstance(result, list)
    assert isinstance(result[0], CVEFinding)
    assert result[0].cve_id == "CVE-2023-12345"
    assert result[0].severidad in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]


# ---------------------------------------------------------------------------
# Test 2: Contrato — input válido, OSV retorna lista vacía
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_contract_lookup_cve_returns_empty_list(httpx_mock: HTTPXMock):
    """
    DADO: OSV.dev no retorna vulnerabilidades para el paquete.
    CUANDO: se invoca lookup_cve("safe-pkg", "1.0.0", "PyPI").
    ENTONCES: el resultado es exactamente una lista vacía [].

    """
    # TODO: Tu código aquí
    httpx_mock.add_response(url = OSV_URL, json= OSV_RESPONSE_EMPTY)
    result = await lookup_cve("safe-pkg", "1.0.0", "PyPI")
    assert result == []


# ---------------------------------------------------------------------------
# Test 3: Contrato — version vacía produce ErrorFinding tipo error_input
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_contract_lookup_cve_error_input_empty_version(httpx_mock: HTTPXMock):
    """
    DADO: se invoca lookup_cve con version="" (vacía).
    CUANDO: lookup_cve("requests", "", "PyPI").
    ENTONCES:
      - El resultado es un ErrorFinding (no una lista).
      - ErrorFinding.tipo == "error_input".
      - ErrorFinding.paquete == "requests".
      - ErrorFinding.ecosistema == "PyPI".
    """
    result = await lookup_cve("requests", "", "PyPI")

    assert isinstance(result, ErrorFinding)
    assert result.tipo == "error_input"
    assert result.paquete == "requests"
    assert result.ecosistema == "PyPI"

# ---------------------------------------------------------------------------
# Test 4: Contrato — error HTTP persistente produce ErrorFinding tipo error_lookup
# ---------------------------------------------------------------------------

@pytest.mark.httpx_mock(can_send_already_matched_responses = True)
@pytest.mark.asyncio
async def test_contract_lookup_cve_error_lookup_after_retries(httpx_mock: HTTPXMock):
    """
    DADO: OSV.dev retorna HTTP 500 en todos los intentos (3 intentos).
    CUANDO: se invoca lookup_cve("requests", "2.28.0", "PyPI").
    ENTONCES:
      - El resultado es un ErrorFinding (no una lista).
      - ErrorFinding.tipo == "error_lookup".
      - ErrorFinding.paquete == "requests".
      - Se hicieron exactamente 3 requests a OSV.dev.

    """
    httpx_mock.add_response(url = OSV_URL, status_code = 500)

    result = await lookup_cve("requests", "2.28.0", "PyPI")
    assert result.tipo == "error_lookup"
    assert len(httpx_mock.get_requests()) == 3
    assert result.paquete == "requests"
    
