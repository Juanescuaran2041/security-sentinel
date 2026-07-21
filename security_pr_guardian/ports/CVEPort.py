from abc import ABC, abstractmethod

from security_pr_guardian.core.models import CandidateFinding, DependencyChange

class CVEPort (ABC):
    """
    Consulta vulnerabilidades conocidas para una lista de paquetes.
    Puerto para la verificación de CVEs en dependencias vía OSV.dev.
    """
    async def get_vulnerabilities (self, packages: list[DependencyChange]) -> list[CandidateFinding]:
        raise NotImplementedError