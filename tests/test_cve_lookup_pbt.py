"""Property-Based Test — Property 8: Límite de dependencias aplicado.

Valida: Requirements 4.6

Propiedad: Para cualquier lista de cambios de dependencias con más de 50 entradas,
el CVE lookup debe consultar exactamente las primeras 50 (por orden de aparición
en el diff) y el resultado debe contener un finding de tipo `limit_exceeded`.

Se usa Hypothesis con @settings(max_examples=100) para generar listas de
dependencias de tamaño variable (51 a 200) y verificar que el invariante
se mantiene en todos los casos.
"""
import asyncio
import json
from dataclasses import dataclass
from unittest.mock import AsyncMock

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from security_pr_guardian.adapters.mcp.cve_lookup_adapter import CVELookUpAdapter
from security_pr_guardian.core.models import DependencyChange, ErrorFinding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@dataclass
class FakeMCPContent:
    text: str


@dataclass
class FakeMCPResponse:
    content: list[FakeMCPContent]


def make_mcp_response(data) -> FakeMCPResponse:
    return FakeMCPResponse(content=[FakeMCPContent(text=json.dumps(data))])


# ---------------------------------------------------------------------------
# Estrategia Hypothesis para generar listas de dependencias
# ---------------------------------------------------------------------------

# Genera un número de dependencias entre 51 y 200
dependency_count_strategy = st.integers(min_value=51, max_value=200)


def build_dependencies(count: int) -> list[DependencyChange]:
    """Genera una lista de `count` dependencias únicas."""
    return [
        DependencyChange(
            manifest_file="requirements.txt",
            package=f"pkg-{i}",
            version=f"1.0.{i}",
            ecosystem="PyPI",
        )
        for i in range(count)
    ]


# ---------------------------------------------------------------------------
# Property 8: Límite de dependencias aplicado
# ---------------------------------------------------------------------------



@settings(max_examples=100)
@given(dep_count=dependency_count_strategy)
def test_property_8_dependency_limit_enforced(dep_count: int):
    """
    PROPIEDAD: Para cualquier conteo de dependencias > 50:
      1. Se consultan EXACTAMENTE las primeras 50 (call_tool se llama 50 veces).
      2. El resultado contiene al menos un ErrorFinding con tipo="limit_exceeded".
      3. La cantidad de omitidas reportada es correcta (dep_count - 50).

    Pistas:
      - Crea un AsyncMock para mcp_session
      - Configura mcp_session.call_tool.return_value = make_mcp_response([])
        (cada paquete retorna lista vacía = sin vulns)
      - Instancia CVELookUpAdapter(mcp_session)
      - Genera la lista con build_dependencies(dep_count)
      - Llama await adapter.lookup_vulnerabilities(deps)
      - Assert 1: mcp_session.call_tool.call_count == 50
      - Assert 2: el último resultado es ErrorFinding con tipo == "limit_exceeded"
      - Assert 3: "Se omitieron {dep_count - 50}" está en error_descripcion

    NOTA sobre Hypothesis + async:
      - hypothesis no soporta nativamente async tests.
      - Puedes usar `asyncio.run()` dentro del test, o usar el decorador
        de pytest-asyncio. Si hay problemas, envuelve la lógica async:
        
        import asyncio
        asyncio.run(tu_coroutine())
    """
    async def _run ():
        #Crear un async mock
        mcp_session = AsyncMock()
        mcp_session.call_tool.return_value = make_mcp_response([])

        adapter = CVELookUpAdapter(mcp_session)
        
        #generar la lista de dependencias
        deps = build_dependencies(dep_count)

        #resultados
        results = await adapter.lookup_vulnerabilities(deps)

        assert mcp_session.call_tool.call_count == 50
        assert results[-1].tipo == "limit_exceeded"
        assert f"Se omitieron {dep_count - 50}" in results[-1].error_descripcion

    asyncio.run(_run())
