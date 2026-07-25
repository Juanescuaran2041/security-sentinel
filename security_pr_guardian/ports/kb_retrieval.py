"""Puerto de recuperacion de base de conocimiento.

Define la interfaz abstracta para recuperar fragmentos relevantes
de la base de conocimiento de seguridad (OWASP/CWE) usando RAG.
"""

from abc import ABC, abstractmethod

from security_pr_guardian.core.models import CandidateFinding, KBFragment


class KBRetrievalPort(ABC):
    """Puerto para la recuperacion de fragmentos de la base de conocimiento.

    Responsabilidades:
    - Recuperar fragmentos relevantes de la KB de seguridad para un finding dado.
    - Aplicar similitud coseno y retornar los top-k resultados.
    - Marcar fragmentos con baja confianza cuando todos los scores < 0.5.
    """

    @abstractmethod
    async def retrieve(self, finding: CandidateFinding, top_k: int = 3) -> list[KBFragment]:
        """Recupera fragmentos relevantes de la base de conocimiento.

        Args:
            finding: Hallazgo candidato para el cual buscar contexto.
            top_k: Numero maximo de fragmentos a retornar (default: 3).

        Returns:
            Lista de fragmentos KB ordenados por relevancia (max top_k).
        """
        ...
