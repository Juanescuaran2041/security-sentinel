"""Puerto de extraccion de diff.

Define la interfaz abstracta para obtener el diff unificado de un PR
y extraer los cambios de dependencias del mismo.
"""

from abc import ABC, abstractmethod

from security_pr_guardian.core.models import DependencyChange


class DiffExtractionPort(ABC):
    """Puerto para la extraccion del diff de un Pull Request.

    Responsabilidades:
    - Obtener el diff unificado de un PR dado (repo + numero de PR).
    - Extraer los cambios de dependencias a partir del diff.
    """

    @abstractmethod
    async def get_diff(self, repo: str, pr_number: int) -> str:
        """Obtiene el diff unificado de un Pull Request.

        Args:
            repo: Identificador del repositorio (formato 'owner/repo').
            pr_number: Numero del Pull Request.

        Returns:
            El diff unificado como string.
        """
        ...

    @abstractmethod
    async def get_dependency_changes(self, diff: str) -> list[DependencyChange]:
        """Extrae los cambios de dependencias del diff.

        Args:
            diff: Diff unificado como string.

        Returns:
            Lista de cambios de dependencias detectados.
        """
        ...
