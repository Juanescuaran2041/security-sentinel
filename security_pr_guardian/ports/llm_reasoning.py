"""Puerto de razonamiento LLM.

Define la interfaz abstracta para la evaluacion de hallazgos candidatos
usando un modelo de lenguaje (Bedrock o Anthropic).
"""

from abc import ABC, abstractmethod

from security_pr_guardian.core.models import CandidateFinding, KBFragment, LLMVerdict, TeamProfile


class LLMReasoningPort(ABC):
    """Puerto para el razonamiento LLM sobre hallazgos de seguridad.

    Responsabilidades:
    - Evaluar si un hallazgo candidato es realmente explotable en su contexto.
    - Ajustar la severidad basandose en el contexto del codigo y la KB.
    - Generar justificacion y recomendacion de remediacion.
    """

    @abstractmethod
    async def evaluate_finding(
        self, finding: CandidateFinding, kb_context: list[KBFragment],
        team_profile: TeamProfile | None = None
    ) -> LLMVerdict:
        """Evalua un hallazgo candidato usando razonamiento LLM.

        Args:
            finding: Hallazgo candidato a evaluar.
            kb_context: Fragmentos de la base de conocimiento como contexto.

        Returns:
            Veredicto del LLM con explotabilidad, severidad ajustada,
            justificacion y recomendacion.
        """
        ...
