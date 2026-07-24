"""Adaptador MCP para consultar CVEs vía el servidor CVE_Lookup.

Implementa CVEPort llamando a la tool `lookup_cve` del servidor MCP
para cada dependencia, con un límite configurable (default 50).
"""

import json

from security_pr_guardian.core.models import CVEFinding, DependencyChange, ErrorFinding
from security_pr_guardian.ports.cve_lookup import CVELookupPort


class CVELookUpAdapter(CVELookupPort):
    """Adaptador que consulta vulnerabilidades CVE vía sesión MCP."""

    def __init__(self, mcp_session, max_dependencies: int = 50):
        self._mcp_session = mcp_session
        self.max_dependencies = max_dependencies

    async def lookup_vulnerabilities(self, packages: list[DependencyChange] ) -> list[CVEFinding | ErrorFinding]:
        limited = packages[: self.max_dependencies]
        omitted = len(packages) - len(limited)

        results: list[CVEFinding | ErrorFinding] = []

        for dep in limited:
            response = await self._mcp_session.call_tool(
                "lookup_cve",
                {
                    "package": dep.package,
                    "version": dep.version,
                    "ecosystem": dep.ecosystem,
                },
            )

            text = response.content[0].text
            data = json.loads(text)

            if isinstance(data, list):
                for item in data:
                    results.append(CVEFinding.model_validate(item))
            else:
                results.append(ErrorFinding.model_validate(data))

        if omitted > 0:
            results.append(
                ErrorFinding(
                    tipo="limit_exceeded",
                    paquete="",
                    version="",
                    ecosistema="",
                    error_descripcion=(
                        f"Se omitieron {omitted} dependencias. "
                        f"Solo se analizaron las primeras {self.max_dependencies}."
                    ),
                )
            )

        return results
