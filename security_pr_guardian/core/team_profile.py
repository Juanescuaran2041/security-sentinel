"""TeamProfileLoader — carga y valida el perfil del equipo desde .security-guardian.yml.

El perfil es completamente opcional. Si el archivo no existe o contiene YAML
inválido, el loader degrada grácilmente devolviendo un `TeamProfile` con
valores por defecto y emitiendo un warning al logger. Nunca lanza excepciones.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

import yaml
from pydantic import ValidationError

from security_pr_guardian.core.models import TeamProfile

if TYPE_CHECKING:
    from security_pr_guardian.core.logger import StructuredLogger

# Nombre canónico del archivo de perfil de equipo
PROFILE_FILENAME = ".security-guardian.yml"

# Logger estándar de Python usado cuando no hay StructuredLogger disponible
_stdlib_logger = logging.getLogger(__name__)


class TeamProfileLoader:
    """Carga el perfil de equipo desde `.security-guardian.yml`.

    Parameters
    ----------
    cwd : Path | str | None
        Directorio de trabajo donde se busca el archivo de perfil.
        Por defecto usa el directorio de trabajo actual del proceso.
    logger : StructuredLogger | None
        Logger estructurado del pipeline. Cuando se proporciona, los
        warnings de carga se emiten como eventos JSON estructurados.
        Si es None, se emite a través del logger estándar de Python.
    analysis_id : str
        Identificador del análisis actual. Solo se usa cuando `logger` es None
        (se incluye en el mensaje de warning del logger estándar).
    """

    def __init__(
        self,
        cwd: Path | str | None = None,
        logger: "StructuredLogger | None" = None,
        analysis_id: str = "unknown",
    ) -> None:
        self._cwd = Path(cwd) if cwd is not None else Path.cwd()
        self._logger = logger
        self._analysis_id = analysis_id

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load(self) -> TeamProfile:
        """Carga y devuelve el `TeamProfile`.

        Siempre retorna una instancia válida de `TeamProfile`:
        - Si el archivo existe y es YAML válido con campos correctos →
          devuelve el perfil parseado.
        - Si el archivo no existe → devuelve `TeamProfile()` (defaults).
        - Si el YAML es inválido o los campos son incorrectos → devuelve
          `TeamProfile()` y emite un warning.

        Returns
        -------
        TeamProfile
            Perfil del equipo (puede ser el de defaults).
        """
        profile_path = self._cwd / PROFILE_FILENAME

        if not profile_path.exists():
            # Archivo ausente — comportamiento esperado, no es un error
            return TeamProfile()

        return self._parse_profile(profile_path)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _parse_profile(self, profile_path: Path) -> TeamProfile:
        """Lee, parsea y valida el archivo de perfil.

        Parameters
        ----------
        profile_path : Path
            Ruta absoluta al archivo `.security-guardian.yml`.

        Returns
        -------
        TeamProfile
            Perfil válido o defaults si ocurre cualquier error.
        """
        try:
            raw_text = profile_path.read_text(encoding="utf-8")
        except OSError as exc:
            self._warn(
                f"No se pudo leer '{profile_path}': {exc}. "
                "Usando perfil de equipo por defecto."
            )
            return TeamProfile()

        try:
            data = yaml.safe_load(raw_text)
        except yaml.YAMLError as exc:
            self._warn(
                f"YAML inválido en '{profile_path}': {exc}. "
                "Usando perfil de equipo por defecto."
            )
            return TeamProfile()

        # safe_load puede retornar None para un archivo vacío
        if data is None:
            return TeamProfile()

        # El archivo puede tener la clave raíz `team_profile` (según el diseño)
        # o los campos directamente al nivel raíz.
        if isinstance(data, dict) and "team_profile" in data:
            profile_data = data["team_profile"]
        else:
            profile_data = data

        if not isinstance(profile_data, dict):
            self._warn(
                f"Estructura inesperada en '{profile_path}': "
                f"se esperaba un mapping, se encontró {type(profile_data).__name__}. "
                "Usando perfil de equipo por defecto."
            )
            return TeamProfile()

        try:
            return TeamProfile.model_validate(profile_data)
        except ValidationError as exc:
            self._warn(
                f"Campos inválidos en '{profile_path}': {exc}. "
                "Usando perfil de equipo por defecto."
            )
            return TeamProfile()

    def _warn(self, message: str) -> None:
        """Emite un warning por el canal apropiado.

        Si hay un `StructuredLogger` disponible, emite un evento JSON
        estructurado con `evento: "team_profile_warning"`.
        En caso contrario usa el logger estándar de Python.

        Parameters
        ----------
        message : str
            Mensaje de advertencia a emitir.
        """
        if self._logger is not None:
            self._logger.log(
                componente="TeamProfileLoader",
                evento="team_profile_warning",
                message=message,
            )
        else:
            _stdlib_logger.warning(
                "[analysis_id=%s] TeamProfileLoader: %s",
                self._analysis_id,
                message,
            )
