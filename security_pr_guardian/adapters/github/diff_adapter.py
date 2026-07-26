"""GitHubDiffAdapter — Implementación de DiffExtractionPort vía API REST de GitHub.

Obtiene el diff unificado de un Pull Request y extrae los cambios
de dependencias utilizando DiffParser internamente.

Reintentos con backoff exponencial (2s, 4s, 8s) en errores HTTP.
Emite evento `analysis_failed` tras 3 reintentos agotados.
"""

from __future__ import annotations

import asyncio

import httpx

from security_pr_guardian.core.diff_parser import DiffParser
from security_pr_guardian.core.logger import StructuredLogger
from security_pr_guardian.core.models import DependencyChange
from security_pr_guardian.ports.diff_extraction import DiffExtractionPort


# Backoff exponencial: 2s, 4s, 8s
_RETRY_DELAYS = [2, 4, 8]
_MAX_RETRIES = 3


class GitHubDiffAdapter(DiffExtractionPort):
    """Adaptador que obtiene diffs de PRs mediante la API REST de GitHub.

    Implementa `DiffExtractionPort` para extraer el diff unificado y
    los cambios de dependencias de un Pull Request.

    Parameters
    ----------
    token : str
        Token de autenticación GitHub (GITHUB_TOKEN).
    logger : StructuredLogger
        Logger estructurado para emitir eventos.
    max_diff_lines : int
        Líneas máximas a procesar del diff. Default: 10000.
    base_url : str
        URL base de la API de GitHub. Default: https://api.github.com.
    """

    def __init__(
        self,
        token: str,
        logger: StructuredLogger,
        max_diff_lines: int = 10_000,
        base_url: str = "https://api.github.com",
    ) -> None:
        self._token = token
        self._logger = logger
        self._parser = DiffParser(max_diff_lines=max_diff_lines)
        self._base_url = base_url.rstrip("/")

    async def get_diff(self, repo: str, pr_number: int) -> str:
        """Obtiene el diff unificado de un Pull Request.

        Llama a la API REST de GitHub con reintentos y backoff exponencial.
        Emite evento `analysis_failed` si todos los reintentos se agotan.

        Args:
            repo: Identificador del repositorio (formato 'owner/repo').
            pr_number: Número del Pull Request.

        Returns:
            El diff unificado como string.

        Raises:
            RuntimeError: Si todos los reintentos se agotan.
        """
        url = f"{self._base_url}/repos/{repo}/pulls/{pr_number}"
        headers = {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/vnd.github.v3.diff",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        last_error: Exception | None = None

        for attempt in range(_MAX_RETRIES):
            try:
                async with httpx.AsyncClient(timeout=30.0) as client:
                    response = await client.get(url, headers=headers)

                    if response.status_code == 200:
                        self._logger.log(
                            componente="GitHubDiffAdapter",
                            evento="diff_fetched",
                            pr_number=pr_number,
                            repo=repo,
                            size_bytes=len(response.text),
                        )
                        return response.text

                    # Non-retryable client errors (except 429)
                    if 400 <= response.status_code < 500 and response.status_code != 429:
                        error_msg = (
                            f"GitHub API returned {response.status_code}: "
                            f"{response.text[:200]}"
                        )
                        self._logger.log(
                            componente="GitHubDiffAdapter",
                            evento="analysis_failed",
                            status_code=response.status_code,
                            repo=repo,
                            pr_number=pr_number,
                            error=error_msg,
                            attempts=attempt + 1,
                        )
                        raise RuntimeError(error_msg)

                    # Retryable: 5xx or 429
                    last_error = httpx.HTTPStatusError(
                        f"HTTP {response.status_code}",
                        request=response.request,
                        response=response,
                    )

            except httpx.HTTPStatusError as exc:
                last_error = exc
            except (httpx.ConnectError, httpx.TimeoutException, httpx.ReadTimeout) as exc:
                last_error = exc

            # Wait with exponential backoff before next attempt
            if attempt < _MAX_RETRIES - 1:
                delay = _RETRY_DELAYS[attempt]
                self._logger.log(
                    componente="GitHubDiffAdapter",
                    evento="retry_scheduled",
                    attempt=attempt + 1,
                    delay_seconds=delay,
                    repo=repo,
                    pr_number=pr_number,
                )
                await asyncio.sleep(delay)

        # All retries exhausted
        error_msg = f"Failed to fetch diff after {_MAX_RETRIES} attempts: {last_error}"
        self._logger.log(
            componente="GitHubDiffAdapter",
            evento="analysis_failed",
            repo=repo,
            pr_number=pr_number,
            error=error_msg,
            attempts=_MAX_RETRIES,
        )
        raise RuntimeError(error_msg)

    async def get_dependency_changes(self, diff: str) -> list[DependencyChange]:
        """Extrae los cambios de dependencias del diff.

        Utiliza DiffParser internamente para parsear el diff y
        detectar manifiestos de dependencias con sus cambios.

        Args:
            diff: Diff unificado como string.

        Returns:
            Lista de cambios de dependencias detectados.
        """
        parse_result = self._parser.parse(diff)

        if parse_result.diff_truncated:
            self._logger.log(
                componente="GitHubDiffAdapter",
                evento="diff_truncated",
                total_added_lines=parse_result.total_added_lines,
                max_diff_lines=self._parser.max_diff_lines,
            )

        if parse_result.manifest_files:
            self._logger.log(
                componente="GitHubDiffAdapter",
                evento="manifests_detected",
                manifests=parse_result.manifest_files,
                dependency_count=len(parse_result.dependency_changes),
            )

        return parse_result.dependency_changes
