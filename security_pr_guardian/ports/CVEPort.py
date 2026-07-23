from abc import ABC, abstractmethod

from security_pr_guardian.core.models import CVEFinding, DependencyChange, ErrorFinding


class CVEPort(ABC):
    """
    Consulta vulnerabilidades conocidas para una lista de paquetes.
    Puerto para la verificación de CVEs en dependencias vía OSV.dev.
    """

    @abstractmethod
    async def lookup_vulnerabilities(
        self, packages: list[DependencyChange]
    ) -> list[CVEFinding | ErrorFinding]:
        raise NotImplementedError
