"""Puerto de analisis estatico.

Define la interfaz abstracta para el analisis estatico (SAST)
sobre el diff unificado de un PR.
"""

from abc import ABC, abstractmethod

from security_pr_guardian.core.models import StaticAnalysisResult


class StaticAnalysisPort(ABC):
    """Puerto para el analisis estatico de seguridad (SAST).

    Responsabilidades:
    - Analizar el diff unificado en busca de patrones de vulnerabilidad
      conocidos (7 CWE objetivo).
    """

    @abstractmethod
    async def analyze_diff(self, diff: str) -> StaticAnalysisResult:
        """Analiza el diff unificado en busca de patrones de vulnerabilidad.

        Args:
            diff: Diff unificado como string.

        Returns:
            Resultado del analisis con findings candidatos y errores parciales.
        """
        ...
