"""GitHubPRCommenterAdapter — Implementación de PRCommentPort vía API REST de GitHub.

Publica o actualiza el comentario de seguridad en un Pull Request.
- Si no existe comentario previo: POST (crea uno nuevo).
- Si ya existe un comentario con la marca de agua: PATCH (lo edita).
- Reintentos con backoff exponencial (2s, 4s, 8s) en errores HTTP.
- Emite evento `comment_publish_failed` tras 3 reintentos agotados.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import httpx
from jinja2 import Environment, FileSystemLoader

from security_pr_guardian.core.logger import StructuredLogger
from security_pr_guardian.core.models import AnalysisResult, ConfirmedFinding
from security_pr_guardian.ports.pr_comment import PRCommentPort


# Marca de agua que identifica los comentarios propios del agente
WATERMARK = "<!-- security-pr-guardian -->"

# Backoff exponencial: 2s, 4s, 8s  (igual que GitHubDiffAdapter)
_RETRY_DELAYS = [2, 4, 8]
_MAX_RETRIES = 3

# Directorio donde vive la plantilla Jinja2
# __file__ = security_pr_guardian/adapters/github/pr_commenter.py
# .parent       → security_pr_guardian/adapters/github/
# .parent.parent → security_pr_guardian/adapters/
# .parent.parent.parent → security_pr_guardian/
# / "templates" → security_pr_guardian/templates/
_TEMPLATES_DIR = Path(__file__).parent.parent.parent / "templates"

_BASE_URL = "https://api.github.com"

class GitHubPRCommenterAdapter(PRCommentPort):
    """Adaptador que publica el comentario de seguridad en un PR de GitHub.

    Implementa `PRCommentPort`. Renderiza el comentario con Jinja2 a partir
    de `pr_comment.md.j2` y lo publica vía la API REST de GitHub.

    Parameters
    ----------
    token : str
        Token de autenticación GitHub (GITHUB_TOKEN).
    logger : StructuredLogger
        Logger estructurado para emitir eventos.
    analysis_result : AnalysisResult
        Resultado completo del análisis (necesario para renderizar la plantilla).
    base_url : str
        URL base de la API de GitHub. Default: https://api.github.com.
    """

    def __init__(self,token: str, logger: StructuredLogger, analysis_result: AnalysisResult, base_url: str = _BASE_URL):
        self._token = token
        self._logger = logger
        self._result = analysis_result
        self._base_url = base_url.rstrip("/")
        # Configurar el entorno Jinja2 apuntando al directorio de plantillas
        self._jinja_env = Environment(
            loader=FileSystemLoader(str(_TEMPLATES_DIR)),
            autoescape=False,  # Markdown, no HTML
        )

    # ------------------------------------------------------------------
    # Puerto principal
    # ------------------------------------------------------------------

    async def post_or_update_comment(self, repo: str, pr_number: int, findings: list[ConfirmedFinding]) -> str:
        """Publica o actualiza el comentario de seguridad en el PR.

        Flujo:
        1. Renderiza el Markdown con la plantilla Jinja2.
        2. Busca si ya existe un comentario con la marca de agua.
        3. Si existe  → PATCH para editarlo.
           Si no existe → POST para crearlo.
        4. Retorna el comment_id resultante.

        Args:
            repo: 'owner/repo'
            pr_number: Número del PR.
            findings: Lista de hallazgos confirmados.

        Returns:
            comment_id como string.
        """
        # Paso 1: renderizar la plantilla
        body = self._render_comment()

        # Paso 2: buscar comentario existente con la marca de agua
        existing_comment_id = await self._find_existing_comment(repo, pr_number)

        # Paso 3: POST o PATCH
        if existing_comment_id:
            comment_id = await self._update_comment(repo, existing_comment_id, body)
        else:
            comment_id = await self._create_comment(repo, pr_number, body)

        return comment_id

    # ------------------------------------------------------------------
    # Renderizado de la plantilla
    # ------------------------------------------------------------------

    def _render_comment(self) -> str:
        """Renderiza `pr_comment.md.j2` con el resultado del análisis.

        Returns:
            El cuerpo del comentario en formato Markdown.
        """
        template = self._jinja_env.get_template("pr_comment.md.j2")
        return template.render(result=self._result)

    # ------------------------------------------------------------------
    # Búsqueda de comentario existente
    # ------------------------------------------------------------------

    async def _find_existing_comment(self, repo: str, pr_number: int) -> str | None:
        """Busca si ya existe un comentario con la marca de agua en el PR.

        Pagina por los comentarios del PR y retorna el ID del primero
        que contenga WATERMARK, o None si no encuentra ninguno.

        Args:
            repo: 'owner/repo'
            pr_number: Número del PR.

        Returns:
            comment_id como string, o None.

        TODO: Implementar la paginación sobre los comentarios del PR.
              Endpoint: GET /repos/{owner}/{repo}/issues/{pr_number}/comments
              Buscar WATERMARK en el campo `body` de cada comentario.
              Retornar str(comment["id"]) del primero que lo contenga.
              Si ninguno lo contiene, retornar None.
              Manejar errores HTTP con un try/except simple
              (si falla, asumir que no hay comentario previo → retornar None).
        """

        
        #Buscar watermark en el campo body de cada commit
        try: 
            async with httpx.AsyncClient() as client:
                url = f"{self._base_url}/repos/{repo}/issues/{pr_number}/comments"
                headers = self._auth_headers()
                
                response = await client.get(url, headers=headers)
                # Si el status es 200 se guarda en comments la respuesta del client
                if response.status_code == 200:
                    comments = response.json()

                    for com in comments:
                        if WATERMARK in com['body']:
                            return str(com['id'])
        except Exception:
            pass

        return None



        # TODO: implementar búsqueda de comentario existente
    # ------------------------------------------------------------------
    # Creación de comentario (POST)
    # ------------------------------------------------------------------

    async def _create_comment(self, repo: str, pr_number: int, body: str) -> str:
        """Crea un comentario nuevo en el PR.

        Endpoint: POST /repos/{owner}/{repo}/issues/{pr_number}/comments
        Payload:  {"body": body}

        Reintentos con backoff exponencial (2s, 4s, 8s).
        Emite `comment_publish_failed` si todos los reintentos fallan.

        Args:
            repo: 'owner/repo'
            pr_number: Número del PR.
            body: Cuerpo del comentario en Markdown.

        Returns:
            comment_id como string.

        Raises:
            RuntimeError: Si todos los reintentos se agotan.

        TODO: Implementar la llamada HTTP con reintentos.
              Fíjate en cómo lo hace GitHubDiffAdapter._retry_request
              para seguir el mismo patrón (bucle for + asyncio.sleep).
              En éxito retornar str(response.json()["id"]).
              En fallo definitivo emitir evento `comment_publish_failed`
              con los campos: analysis_id, http_status, attempts.
        """
        async with httpx.AsyncClient() as client:
            url = f"{self._base_url}/repos/{repo}/issues/{pr_number}/comments"
            headers = self._auth_headers()
            payload = {"body": body}
            attempt = 0

            lasts_status = None

            for attempt in range(_MAX_RETRIES):
                try:
                    response = await client.post(url, headers=headers, json=payload)
                    lasts_status = response.status_code
                    if response.status_code == 201:
                        return str(response.json()['id'])

                except Exception:
                    lasts_status = None

                if attempt < _MAX_RETRIES - 1:
                    await asyncio.sleep(_RETRY_DELAYS[attempt])
            
            self._logger.log(
                componente="GitHubPRCommenterAdapter",
                evento= "comment_publish_failed",
                analysis_id=self._result.analysis_id,
                http_status=lasts_status,
                attempts=_MAX_RETRIES,
            )
            raise RuntimeError("Failed to publish comment after all retries.")
            
                    


 
    # ------------------------------------------------------------------
    # Actualización de comentario (PATCH)
    # ------------------------------------------------------------------

    async def _update_comment(self, repo: str, comment_id: str, body: str) -> str:
        """Actualiza un comentario existente en el PR.

        Endpoint: PATCH /repos/{owner}/{repo}/issues/comments/{comment_id}
        Payload:  {"body": body}

        Misma lógica de reintentos que _create_comment.

        Args:
            repo: 'owner/repo'
            comment_id: ID del comentario a actualizar.
            body: Nuevo cuerpo del comentario en Markdown.

        Returns:
            comment_id como string (el mismo que recibió).

        Raises:
            RuntimeError: Si todos los reintentos se agotan.

        TODO: Implementar igual que _create_comment pero con PATCH.
              Endpoint distinto: /repos/{owner}/{repo}/issues/comments/{comment_id}
              En éxito retornar comment_id (ya lo tienes, no cambia).
        """
        
        async with httpx.AsyncClient() as client:
            url = f"{self._base_url}/repos/{repo}/issues/comments/{comment_id}"
            headers = self._auth_headers()
            payload = {"body": body}
            
            attempt = 0
            lasts_status = None

            for attempt in range(_MAX_RETRIES):
                try:
                    response = await client.patch(url, headers=headers, json=payload)
                    lasts_status = response.status_code
                    if response.status_code == 200:
                        return comment_id

                except Exception:
                    lasts_status = None

                if attempt < _MAX_RETRIES - 1:
                    await asyncio.sleep(_RETRY_DELAYS[attempt])

            self._logger.log(
                componente="GitHubPRCommenterAdapter",
                evento= "comment_publish_failed",
                analysis_id=self._result.analysis_id,
                http_status=lasts_status,
                attempts=_MAX_RETRIES,
            )

            raise RuntimeError("Failed to update comment after all retries.")

    # ------------------------------------------------------------------
    # Helper: headers comunes
    # ------------------------------------------------------------------

    def _auth_headers(self) -> dict[str, str]:
        """Retorna los headers de autenticación para la API de GitHub."""
        return {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
