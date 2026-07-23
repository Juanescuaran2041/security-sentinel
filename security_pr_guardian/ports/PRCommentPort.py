from abc import ABC, abstractmethod

from security_pr_guardian.core.model import ConfirmedFinding

class PRCommentPort (ABC):
    
    @abstractmethod
    async def post_or_update_pr (repo:str, pr_number:int, findings:list[ConfirmedFinding]) -> str:

        """
        Publica (POST) o edita (PATCH, vía watermark) el comentario del PR.
        Returns:
            str: URL del comentario creado o actualizado.
        """
        raise NotImplementedError