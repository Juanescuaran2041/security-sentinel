"""Puerto de consulta de CVEs.

Define la interfaz abstracta para buscar vulnerabilidades conocidas (CVEs)
en las dependencias modificadas de un PR.
"""

from abc import ABC, abstractmethod

from security_pr_guardian.core.models import CVEFinding, DependencyChange


class CVELookupPort(ABC):
    """Puerto para la consulta de vulnerabilidades CVE en dependencias.

    Responsabilidades:
    - Consultar servicios externos (OSV.dev) por vulnerabilidades conocidas
      en las dependencias modificadas.
    - Aplicar el limite de 50 dependencias por consulta.
    """

    @abstractmethod
    async def lookup_vulnerabilities(
        self, packages: list[DependencyChange]
    ) -> list[CVEFinding]:
        """Busca vulnerabilidades conocidas en las dependencias proporcionadas.

        Args:
            packages: Lista de cambios de dependencias a consultar.

        Returns:
            Lista de hallazgos CVE encontrados.
        """
        ...
