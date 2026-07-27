"""AutoDetector — escanea el proyecto para pre-rellenar el TeamProfile.

Detecta frameworks, librerías de auth y severidad mínima leyendo los archivos
de manifiesto del directorio de trabajo. Diseñado para ser llamado por el
comando `security-guardian init --profile --auto-detect`.

No lanza excepciones — si un archivo no existe o no es parseable, simplemente
no aporta datos y continúa.
"""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# Mapeos de detección
# ---------------------------------------------------------------------------

# Frameworks detectados por presencia de su nombre en las dependencias
# Clave: nombre del paquete tal como aparece en el manifiesto
# Valor: nombre canónico a mostrar al usuario
_FRAMEWORK_MAP: dict[str, str] = {
    # Python
    "django": "django",
    "flask": "flask",
    "fastapi": "fastapi",
    "tornado": "tornado",
    "aiohttp": "aiohttp",
    "starlette": "starlette",
    # JavaScript / Node
    "express": "express",
    "react": "react",
    "vue": "vue",
    "angular": "@angular/core",
    "next": "next",
    "nuxt": "nuxt",
    "svelte": "svelte",
    "nestjs": "@nestjs/core",
    # Rust
    "actix-web": "actix-web",
    "axum": "axum",
    "rocket": "rocket",
}

# Librerías de autenticación / hashing reconocidas
_AUTH_LIBRARY_MAP: dict[str, str] = {
    # Python hashing
    "bcrypt": "bcrypt",
    "argon2-cffi": "argon2-cffi",
    "passlib": "passlib",
    "cryptography": "cryptography",
    # Python auth
    "django-allauth": "django-allauth",
    "python-jose": "python-jose",
    "authlib": "authlib",
    "pyjwt": "pyjwt",
    # JavaScript
    "bcryptjs": "bcryptjs",
    "passport": "passport",
    "jsonwebtoken": "jsonwebtoken",
    "jose": "jose",
    "next-auth": "next-auth",
}

# Mapeo de severidad desde configuraciones de linters conocidas
# Clave: valor que puede aparecer en el archivo de config del linter
# Valor: severity string que usa TeamProfile
_SEVERITY_MAP: dict[str, str] = {
    "error": "high",
    "warning": "medium",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}


# ---------------------------------------------------------------------------
# Resultado de la detección
# ---------------------------------------------------------------------------

@dataclass
class DetectionResult:
    """Resultado del escaneo automático del proyecto."""

    frameworks: list[str] = field(default_factory=list)
    auth_libraries: list[str] = field(default_factory=list)
    min_severity: str | None = None  # None = no detectado, 

# ---------------------------------------------------------------------------
# AutoDetector
# ---------------------------------------------------------------------------

class AutoDetector:
    """Escanea el directorio de trabajo para detectar frameworks y librerías.

    Parameters
    ----------
    cwd : Path | str | None
        Directorio raíz del proyecto a escanear.
        Por defecto usa el directorio de trabajo actual.
    """

    def __init__(self, cwd: Path | str | None = None) -> None:
        self._cwd = Path(cwd) if cwd is not None else Path.cwd()

    def detect(self) -> DetectionResult:
        """Ejecuta el escaneo completo y retorna los resultados detectados.

        Returns
        -------
        DetectionResult
            Frameworks, librerías de auth y severidad mínima detectados.
            Cualquier campo no detectado queda como lista vacía / None.
        """
        result = DetectionResult()

        # Recolectar todos los nombres de paquetes de todos los manifiestos
        all_packages: set[str] = set()
        all_packages.update(self._parse_requirements_txt())
        all_packages.update(self._parse_pyproject_toml())
        all_packages.update(self._parse_package_json())
        all_packages.update(self._parse_cargo_toml())

        # Detectar frameworks
        result.frameworks = self._match_packages(all_packages, _FRAMEWORK_MAP)

        # Detectar librerías de auth
        result.auth_libraries = self._match_packages(all_packages, _AUTH_LIBRARY_MAP)

        # Detectar severidad mínima desde linters
        result.min_severity = self._detect_min_severity()

        return result

    # ------------------------------------------------------------------
    # Parsers por tipo de manifiesto — implementa tú la lógica interna
    # ------------------------------------------------------------------

    def _parse_requirements_txt(self) -> list[str]:
        """Extrae nombres de paquetes de requirements.txt.

        TODO (14.5): parsear cada línea, ignorar comentarios y opciones (-r,
        --index-url, etc.), normalizar el nombre (minúsculas, guiones).
        Retorna lista de nombres de paquetes en minúsculas.
        """
        path = self._cwd / "requirements.txt"
        if not path.exists():
            return []
        
        lines = path.read_text(encoding="utf-8").splitlines()

        packages = []

        for line in lines:
            line = line.strip()

            if not line or line.startswith("#") or line.startswith("-"):
                continue
        
            # Eliminar extras como paquetes
            line = re.split(r"[\[;]", line)[0]

            # Quitar especificadores de versión: ==, >=, <=, ~=, !=, >
            name = re.split(r"[><=!~@]", line)[0].strip()

            if name:
                packages.append(self._normalize_package_name(name))
        
        return packages


    def _parse_pyproject_toml(self) -> list[str]:
        """Extrae dependencias de pyproject.toml (secciones dependencies y
        optional-dependencies para PEP 621, y [tool.poetry.dependencies]).

        TODO (14.5): usar tomllib (Python 3.11+) para parsear el TOML.
        """
        path = self._cwd / "pyproject.toml"
        if not path.exists():
            return []
        
        try:
            line = path.read_text(encoding="utf-8")
            data = tomllib.loads(line)
        except (OSError, Exception):
            return []


        packages = []
        # Primero encuenta la seccion de proyecto y obtiene despues sus dependencias
        project_dependencies = data.get("project", {}).get("dependencies", [])
        

        for dep in project_dependencies:
            name = re.split(r"[\[><=!~@; ]", dep)[0].strip()

            if name:
                packages.append(self._normalize_package_name(name))

        poetry_dependencies = data.get("tool", {}).get("poetry", {}).get("dependencies", {})

        for name in poetry_dependencies:
            if name.lower() != "python":
                packages.append(self._normalize_package_name(name))

        return packages



    def _parse_package_json(self) -> list[str]:
        """Extrae dependencias de package.json (dependencies + devDependencies).

        TODO (14.5): parsear JSON, retornar claves de ambas secciones.
        """
        path = self._cwd / "package.json"
        if not path.exists():
            return []
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []

        packages = []
        for section in ("dependencies", "devDependencies"):
            for name in data.get(section, {}):
                packages.append(name.lower())
        return packages

    def _parse_cargo_toml(self) -> list[str]:
        path = self._cwd / "Cargo.toml"
        if not path.exists():
            return []
        try:
            import tomllib
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, Exception):
            return []

        packages = []
        for section in ("dependencies", "dev-dependencies"):
            for name in data.get(section, {}):
                packages.append(self._normalize_package_name(name))
        return packages         

    def _detect_min_severity(self) -> str | None:
        """Infiere severidad mínima desde configuraciones de linters.

        Busca en .bandit y ruff.toml. Retorna el string de severidad o None
        si no se puede inferir — el caller usará "low" como default.
        """
        # --- .bandit ---
        # Formato ini: level = LOW | MEDIUM | HIGH bajo [bandit] u otras secciones
        bandit_path = self._cwd / ".bandit"
        if bandit_path.exists():
            try:
                text = bandit_path.read_text(encoding="utf-8")
                match = re.search(r"^\s*level\s*=\s*(\w+)", text, re.IGNORECASE | re.MULTILINE)
                if match:
                    level = match.group(1).lower()
                    if level in _SEVERITY_MAP:
                        return _SEVERITY_MAP[level]
            except OSError:
                pass

        # --- ruff.toml ---
        # ruff no tiene un campo "severity" directo, pero si existe el archivo
        # podemos inferir que el equipo usa ruff como linter principal,
        # lo que suele correlacionar con un estándar medio.
        # Si en el futuro ruff añade severidad, se puede extender aquí.
        ruff_path = self._cwd / "ruff.toml"
        if ruff_path.exists():
            try:
                import tomllib
                data = tomllib.loads(ruff_path.read_text(encoding="utf-8"))
                # Campo no estándar pero documentado en algunos setups de equipo
                level = (
                    data.get("lint", {}).get("severity")
                    or data.get("severity")
                )
                if level and isinstance(level, str) and level.lower() in _SEVERITY_MAP:
                    return _SEVERITY_MAP[level.lower()]
            except (OSError, Exception):
                pass

        return None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _match_packages(
        self,
        detected_packages: set[str],
        mapping: dict[str, str],
    ) -> list[str]:
        """Cruza los paquetes detectados contra un mapa de nombres conocidos.

        Parameters
        ----------
        detected_packages : set[str]
            Nombres de paquetes en minúsculas tal como aparecen en manifiestos.
        mapping : dict[str, str]
            Mapa de nombre_en_manifiesto → nombre_canónico.

        Returns
        -------
        list[str]
            Nombres canónicos de los paquetes que coincidieron, ordenados.
        """
        matched = []
        for pkg_key, canonical in mapping.items():
            if pkg_key.lower() in detected_packages:
                matched.append(canonical)
        return sorted(matched)

    def _normalize_package_name(self, name: str) -> str:
        """Normaliza un nombre de paquete a minúsculas con guiones.

        PEP 503: underscore, hyphen y dot son equivalentes en PyPI.
        Para npm y Cargo se deja en minúsculas sin más transformación.
        """
        return re.sub(r"[-_.]+", "-", name).lower()


# ---------------------------------------------------------------------------
# Funciones de conveniencia a nivel de módulo (usadas por la CLI)
# ---------------------------------------------------------------------------


def detect_frameworks(cwd: Path | str | None = None) -> list[str]:
    """Detecta frameworks del proyecto escaneando manifiestos.

    Parameters
    ----------
    cwd : Path | str | None
        Directorio raíz del proyecto. Por defecto el directorio actual.

    Returns
    -------
    list[str]
        Nombres canónicos de frameworks detectados (ordenados).
    """
    return AutoDetector(cwd=cwd).detect().frameworks


def detect_auth_libraries(cwd: Path | str | None = None) -> list[str]:
    """Detecta librerías de autenticación/hashing del proyecto.

    Parameters
    ----------
    cwd : Path | str | None
        Directorio raíz del proyecto. Por defecto el directorio actual.

    Returns
    -------
    list[str]
        Nombres canónicos de librerías de auth detectadas (ordenados).
    """
    return AutoDetector(cwd=cwd).detect().auth_libraries


def detect_min_severity(cwd: Path | str | None = None) -> str | None:
    """Infiere la severidad mínima desde archivos de configuración de linters.

    Parameters
    ----------
    cwd : Path | str | None
        Directorio raíz del proyecto. Por defecto el directorio actual.

    Returns
    -------
    str | None
        Nivel de severidad inferido ('critical', 'high', 'medium', 'low')
        o None si no se pudo inferir.
    """
    return AutoDetector(cwd=cwd).detect().min_severity


def auto_detect_profile(cwd: Path | str | None = None) -> dict:
    """Ejecuta la detección completa y retorna un dict con los valores pre-rellenados.

    Combina detección de frameworks, librerías de auth y severidad mínima
    en un único diccionario listo para ser usado como defaults del cuestionario.

    Parameters
    ----------
    cwd : Path | str | None
        Directorio raíz del proyecto. Por defecto el directorio actual.

    Returns
    -------
    dict
        Diccionario con claves 'frameworks', 'auth_libraries', 'min_severity'.
        Los campos no detectados tienen valores vacíos o None.
    """
    result = AutoDetector(cwd=cwd).detect()
    return {
        "frameworks": result.frameworks,
        "auth_libraries": result.auth_libraries,
        "min_severity": result.min_severity,
    }