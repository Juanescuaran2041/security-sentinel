"""Puerto de comentarios en Pull Requests.

Define la interfaz abstracta para publicar o actualizar comentarios
de seguridad en un Pull Request de GitHub.
"""

from abc import ABC, abstractmethod

from security_pr_guardian.core.models import ConfirmedFinding


class PRCommentPort(ABC):
    """Puerto para la publicacion de comentarios en Pull Requests.

    Responsabilidades:
    - Publicar un nuevo comentario con los hallazgos confirmados.
    - Actualizar un comentario existente (detectado por marca de agua).
    - Manejar reintentos en caso de fallos de la API de GitHub.
    """

    @abstractmethod
    async def post_or_update_comment(
        self, repo: str, pr_number: int, findings: list[ConfirmedFinding]
    ) -> str:
        """Publica o actualiza el comentario de seguridad en un PR.

        Args:
            repo: Identificador del repositorio (formato 'owner/repo').
            pr_number: Numero del Pull Request.
            findings: Lista de hallazgos confirmados a reportar.

        Returns:
            El comment_id del comentario creado o actualizado.
        """
        ...
