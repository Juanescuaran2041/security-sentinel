"""Adaptador MCP para análisis estático — implementa StaticAnalysisPort.

Conecta el puerto de análisis estático con el PatternEngine del servidor
MCP `static_analyzer_server`. Para el MVP, instancia PatternEngine
directamente (llamada en-proceso) replicando la lógica del servidor
(timeout de 60 s, errores parciales). En producción, este adaptador
podría usar el cliente SDK de MCP con transporte stdio para comunicarse
con el servidor como proceso independiente.

Requisitos cubiertos:
  - Req 2.3: StaticAnalyzerMCPAdapter implementa StaticAnalysisPort.
"""

from __future__ import annotations

import asyncio
import logging

from security_pr_guardian.adapters.mcp.pattern_engine import PatternEngine
from security_pr_guardian.core.models import StaticAnalysisResult
from security_pr_guardian.ports.static_analysis import StaticAnalysisPort

logger = logging.getLogger(__name__)

ANALYSIS_TIMEOUT_SECONDS = 60


class StaticAnalyzerMCPAdapter(StaticAnalysisPort):
    """Adaptador que implementa StaticAnalysisPort delegando al PatternEngine.

    Para el MVP, invoca directamente el PatternEngine (la misma lógica que
    usa el servidor FastMCP) con el mismo timeout de 60 s y manejo de errores
    parciales. Esto evita la complejidad de configurar transporte stdio/SSE
    para testing, manteniendo la misma interfaz que usaría un cliente MCP real.
    """

    def __init__(self, engine: PatternEngine | None = None) -> None:
        """Inicializa el adaptador con un PatternEngine opcional.

        Args:
            engine: Instancia de PatternEngine a usar. Si es None, se crea
                    una instancia con las reglas por defecto.
        """
        self._engine = engine if engine is not None else PatternEngine()

    async def analyze_diff(self, diff: str) -> StaticAnalysisResult:
        """Analiza el diff unificado delegando al PatternEngine.

        Ejecuta el análisis en un thread para no bloquear el event loop,
        con un timeout de 60 s. Si se excede el timeout, retorna un
        resultado vacío con error parcial indicativo.

        Args:
            diff: Diff unificado como string (formato git diff / GitHub PR).

        Returns:
            StaticAnalysisResult con findings candidatos y errores parciales.
        """
        logger.debug(
            "StaticAnalyzerMCPAdapter: iniciando análisis de diff (%d chars)", len(diff)
        )

        try:
            result = await asyncio.wait_for(
                asyncio.to_thread(self._engine.analyze, diff),
                timeout=ANALYSIS_TIMEOUT_SECONDS,
            )
            logger.debug(
                "StaticAnalyzerMCPAdapter: análisis completado — %d findings, %d errores parciales",
                len(result.findings),
                len(result.errores_parciales),
            )
            return result
        except asyncio.TimeoutError:
            logger.error(
                "StaticAnalyzerMCPAdapter: análisis excedió timeout de %d s",
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
            logger.exception("StaticAnalyzerMCPAdapter: error inesperado durante análisis")
            return StaticAnalysisResult(
                findings=[],
                errores_parciales=[
                    {
                        "archivo": "_adapter",
                        "error": f"Error en adaptador MCP: {exc}",
                    }
                ],
            )
