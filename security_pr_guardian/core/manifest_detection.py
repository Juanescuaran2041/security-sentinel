"""Detección de manifiestos de dependencias por nombre canónico.

Define el conjunto de nombres de archivo reconocidos como manifiestos
de dependencias y la función de detección que opera sobre basenames.
"""

import os

MANIFEST_NAMES: frozenset[str] = frozenset({
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "requirements.txt",
    "Pipfile",
    "Pipfile.lock",
    "poetry.lock",
    "pyproject.toml",
    "Cargo.toml",
    "Cargo.lock",
    "vcpkg.json",
    "go.mod",
    "go.sum",
    "pom.xml",
    "build.gradle",
})


def is_manifest(filename: str) -> bool:
    """Determina si un nombre de archivo es un manifiesto de dependencias conocido.

    Compara el basename del archivo contra el conjunto canónico de nombres.

    Args:
        filename: Nombre del archivo (puede incluir ruta, se usa solo el basename).

    Returns:
        True si el basename está en MANIFEST_NAMES.
    """
    basename = os.path.basename(filename)
    return basename in MANIFEST_NAMES
