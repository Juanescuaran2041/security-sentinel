"""Servidor FastMCP Static Analyzer — análisis estático SAST sobre diffs.

Expone la tool `analyze_diff(diff: str)` que ejecuta PatternEngine sobre
el diff unificado de un PR y retorna hallazgos candidatos con manejo de
errores parciales por archivo.

Requisitos cubiertos:
  - Req 2.2: static_analyzer_server expuesto como MCP tool.
  - Timeout de 60 s máximo; si se excede, retorna resultados parciales.
  - errores_parciales incluye errores por archivo detectados por PatternEngine.
"""

import asyncio
import logging

from mcp.server.fastmcp import FastMCP

from security_pr_guardian.adapters.mcp.pattern_engine import PatternEngine
from security_pr_guardian.core.models import StaticAnalysisResult

logger = logging.getLogger(__name__)

ANALYSIS_TIMEOUT_SECONDS = 60

mcp = FastMCP("static-analyzer")

_engine = PatternEngine()


@mcp.tool()
async def analyze_diff(diff: str) -> StaticAnalysisResult:
    """Analiza un diff unificado en busca de patrones de vulnerabilidad.

    Ejecuta PatternEngine sobre las líneas añadidas del diff y retorna
    hallazgos candidatos con errores parciales por archivo. El análisis
    se interrumpe a los 60 s y retorna resultados parciales si se excede
    el timeout.

    Args:
        diff: Diff unificado completo (formato git diff / GitHub PR diff).

    Returns:
        StaticAnalysisResult con findings candidatos y errores parciales.
    """
    try:
        result = await asyncio.wait_for(
            asyncio.to_thread(_engine.analyze, diff),
            timeout=ANALYSIS_TIMEOUT_SECONDS,
        )
        return result
    except asyncio.TimeoutError:
        logger.error(
            "Análisis estático excedió el timeout de %d s",
            ANALYSIS_TIMEOUT_SECONDS,
        )
        return StaticAnalysisResult(
            findings=[],
            errores_parciales=[
                {
                    "archivo": "_timeout",
                    "error": (
                        f"El análisis excedió el límite de "
                        f"{ANALYSIS_TIMEOUT_SECONDS} segundos"
                    ),
                }
            ],
        )
    except Exception as exc:
        logger.exception("Error inesperado en analyze_diff")
        return StaticAnalysisResult(
            findings=[],
            errores_parciales=[
                {
                    "archivo": "_internal",
                    "error": f"Error inesperado: {exc}",
                }
            ],
        )


if __name__ == "__main__":
    mcp.run()
