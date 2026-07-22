from abc import ABC, abstractmethod

from security_pr_guardian.core.models import LLMVerdict, KBFragment, CandidateFinding
from security_pr_guardian.core.exceptions import LLMEValidationError

class LLMReasoningPort(ABC):

    @abstractmethod
    async def evaluate_finding(self, finding: CandidateFinding, kb_context: list[KBFragment]) -> LLMVerdict:
        """Evalúa si el finding es explotable en su contexto real.

        Nota: el manejo de "no_evaluado" (JSON inválido / campos faltantes /
        fallo tras reintentos) es responsabilidad del adaptador concreto:
        decide si eso se resuelve con una excepción capturada por el agente
        o con un LLMVerdict "neutro" — mantenlo consistente entre
        BedrockAdapter y AnthropicAdapter.
        """
        raise NotImplementedError

    


