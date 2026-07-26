"""DiffParser — Extracción de datos del diff unificado.

Responsabilidades:
- Extraer líneas añadidas (`+`) del diff unificado.
- Detectar manifiestos de dependencias en los archivos modificados.
- Extraer cambios de dependencias (`DependencyChange`) de los manifiestos.
- Truncar el diff a `max_diff_lines` con activación del flag `diff_truncated`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from security_pr_guardian.core.manifest_detection import MANIFEST_NAMES, is_manifest
from security_pr_guardian.core.models import DependencyChange


# ---------------------------------------------------------------------------
# Regex patterns for unified diff parsing
# ---------------------------------------------------------------------------

_DIFF_FILE_HEADER = re.compile(r"^\+\+\+ b/(.+)$")
_HUNK_HEADER = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")

# ---------------------------------------------------------------------------
# Dependency extraction patterns by ecosystem
# ---------------------------------------------------------------------------

# Python: requirements.txt, Pipfile, pyproject.toml, poetry.lock, Pipfile.lock
_RE_REQUIREMENTS_TXT = re.compile(
    r"""^
    \s*([A-Za-z0-9][\w.\-]*)  # package name
    \s*[=~<>!]=*\s*           # version specifier
    ([^\s;#,]+)               # version string
    """,
    re.VERBOSE,
)

# package.json / package-lock.json / yarn.lock style: "package": "^version"
_RE_JSON_DEPENDENCY = re.compile(
    r"""
    ["\']([^"\'@][^"\']*)["\']  # package name
    \s*:\s*
    ["\'][~^>=<]*               # version prefix chars
    ([0-9][^"\']*)["\']         # version
    """,
    re.VERBOSE,
)

# Cargo.toml: name = "version" or name = { version = "..." }
_RE_CARGO_TOML = re.compile(
    r"""
    ^([A-Za-z0-9][\w\-]*)      # package name
    \s*=\s*
    (?:
        ["\']([0-9][^"\']*)["\']  # simple version string
        |
        \{[^}]*version\s*=\s*["\']([0-9][^"\']*)["\']  # inline table
    )
    """,
    re.VERBOSE,
)

# go.mod: require module v1.2.3
_RE_GO_MOD = re.compile(
    r"""^\s*
    ([^\s]+)    # module path
    \s+
    (v[\d]+\.[^\s]+)  # version with v prefix
    """,
    re.VERBOSE,
)

# pom.xml: <version>x.y.z</version> preceded by <artifactId>name</artifactId>
# Simplified: detect <artifactId> and <version> on added lines
_RE_POM_ARTIFACT = re.compile(r"<artifactId>\s*([^<]+)\s*</artifactId>")
_RE_POM_VERSION = re.compile(r"<version>\s*([^<]+)\s*</version>")

# build.gradle: implementation 'group:name:version' or implementation "group:name:version"
_RE_GRADLE = re.compile(
    r"""
    (?:implementation|api|compile|runtimeOnly|testImplementation)
    \s*[\(\s]*['\"]
    ([^:'"]+):([^:'"]+):([^'"]+)  # group:name:version
    ['\"]
    """,
    re.VERBOSE,
)

# vcpkg.json: "name": "pkg", "version>=": "x.y.z"
_RE_VCPKG_NAME = re.compile(r'"name"\s*:\s*"([^"]+)"')
_RE_VCPKG_VERSION = re.compile(r'"version[^"]*"\s*:\s*"([^"]+)"')

# Ecosystem mapping by manifest filename
_ECOSYSTEM_MAP: dict[str, str] = {
    "package.json": "npm",
    "package-lock.json": "npm",
    "yarn.lock": "npm",
    "requirements.txt": "PyPI",
    "Pipfile": "PyPI",
    "Pipfile.lock": "PyPI",
    "poetry.lock": "PyPI",
    "pyproject.toml": "PyPI",
    "Cargo.toml": "crates.io",
    "Cargo.lock": "crates.io",
    "go.mod": "Go",
    "go.sum": "Go",
    "pom.xml": "Maven",
    "build.gradle": "Maven",
    "vcpkg.json": "vcpkg",
}


@dataclass
class ParsedLine:
    """A parsed added line from the diff."""

    file: str
    line_number: int
    content: str


@dataclass
class DiffParseResult:
    """Result of parsing a unified diff."""

    added_lines: list[ParsedLine] = field(default_factory=list)
    manifest_files: list[str] = field(default_factory=list)
    dependency_changes: list[DependencyChange] = field(default_factory=list)
    diff_truncated: bool = False
    total_added_lines: int = 0


class DiffParser:
    """Parser de diffs unificados para Security PR Guardian.

    Extrae líneas añadidas, detecta manifiestos de dependencias,
    extrae cambios de dependencias, y trunca diffs que excedan
    el límite configurado.

    Parameters
    ----------
    max_diff_lines : int
        Número máximo de líneas añadidas a procesar. Default: 10000.
    """

    def __init__(self, max_diff_lines: int = 10_000) -> None:
        self.max_diff_lines = max_diff_lines

    def parse(self, diff: str) -> DiffParseResult:
        """Parsea un diff unificado completo.

        Args:
            diff: Diff unificado en formato git diff / GitHub PR diff.

        Returns:
            DiffParseResult con líneas añadidas, manifiestos detectados,
            cambios de dependencias y flag de truncación.
        """
        result = DiffParseResult()
        current_file: str | None = None
        current_line: int = 0
        added_count: int = 0
        truncated = False

        for raw_line in diff.splitlines():
            # Detect file header: +++ b/path/to/file
            file_match = _DIFF_FILE_HEADER.match(raw_line)
            if file_match:
                current_file = file_match.group(1)
                current_line = 0

                # Check if this file is a manifest
                if is_manifest(current_file) and current_file not in result.manifest_files:
                    result.manifest_files.append(current_file)
                continue

            # Detect hunk header: @@ -x,y +x,y @@
            hunk_match = _HUNK_HEADER.match(raw_line)
            if hunk_match:
                current_line = int(hunk_match.group(1))
                continue

            # Skip lines without a file context
            if current_file is None:
                continue

            # Process added lines (prefix '+')
            if raw_line.startswith("+") and not raw_line.startswith("+++"):
                added_count += 1

                # Check truncation limit
                if added_count > self.max_diff_lines:
                    truncated = True
                    # Don't process lines beyond the limit
                    continue

                code_line = raw_line[1:]  # Strip '+' prefix

                parsed = ParsedLine(
                    file=current_file,
                    line_number=current_line,
                    content=code_line,
                )
                result.added_lines.append(parsed)

                current_line += 1
            elif raw_line.startswith("-") and not raw_line.startswith("---"):
                # Deleted lines don't affect new-file line counter
                pass
            else:
                # Context lines advance the line counter
                if not raw_line.startswith("---") and not raw_line.startswith("\\"):
                    current_line += 1

        result.diff_truncated = truncated
        result.total_added_lines = added_count

        # Extract dependency changes from manifest files
        result.dependency_changes = self._extract_dependencies(result)

        return result

    def truncate_diff(self, diff: str) -> tuple[str, bool]:
        """Trunca un diff al límite de max_diff_lines líneas añadidas.

        Retorna el diff truncado y un flag indicando si se truncó.

        Args:
            diff: Diff unificado completo.

        Returns:
            Tupla (diff_truncado, fue_truncado).
        """
        lines = diff.splitlines()
        output_lines: list[str] = []
        added_count = 0
        truncated = False

        for line in lines:
            if line.startswith("+") and not line.startswith("+++"):
                added_count += 1
                if added_count > self.max_diff_lines:
                    truncated = True
                    break
            output_lines.append(line)

        return "\n".join(output_lines), truncated

    def _extract_dependencies(self, result: DiffParseResult) -> list[DependencyChange]:
        """Extrae cambios de dependencias de las líneas añadidas en manifiestos.

        Solo procesa líneas que pertenecen a archivos detectados como manifiestos.
        """
        dependencies: list[DependencyChange] = []

        # Group added lines by manifest file
        manifest_lines: dict[str, list[str]] = {}
        for parsed_line in result.added_lines:
            if parsed_line.file in result.manifest_files:
                manifest_lines.setdefault(parsed_line.file, []).append(
                    parsed_line.content
                )

        for manifest_file, lines in manifest_lines.items():
            ecosystem = self._get_ecosystem(manifest_file)
            deps = self._parse_manifest_lines(manifest_file, lines, ecosystem)
            dependencies.extend(deps)

        return dependencies

    def _get_ecosystem(self, manifest_file: str) -> str:
        """Determina el ecosistema a partir del nombre del manifiesto."""
        import os

        basename = os.path.basename(manifest_file)
        return _ECOSYSTEM_MAP.get(basename, "unknown")

    def _parse_manifest_lines(
        self, manifest_file: str, lines: list[str], ecosystem: str
    ) -> list[DependencyChange]:
        """Parsea las líneas añadidas de un manifiesto y extrae dependencias."""
        import os

        basename = os.path.basename(manifest_file)

        if basename == "requirements.txt":
            return self._parse_requirements_txt(manifest_file, lines, ecosystem)
        elif basename in ("package.json", "package-lock.json"):
            return self._parse_json_deps(manifest_file, lines, ecosystem)
        elif basename == "yarn.lock":
            return self._parse_yarn_lock(manifest_file, lines, ecosystem)
        elif basename in ("Pipfile", "pyproject.toml"):
            return self._parse_toml_style(manifest_file, lines, ecosystem)
        elif basename in ("Pipfile.lock", "poetry.lock"):
            return self._parse_lock_json_style(manifest_file, lines, ecosystem)
        elif basename == "Cargo.toml":
            return self._parse_cargo_toml(manifest_file, lines, ecosystem)
        elif basename == "Cargo.lock":
            return self._parse_cargo_lock(manifest_file, lines, ecosystem)
        elif basename in ("go.mod", "go.sum"):
            return self._parse_go_mod(manifest_file, lines, ecosystem)
        elif basename == "pom.xml":
            return self._parse_pom_xml(manifest_file, lines, ecosystem)
        elif basename == "build.gradle":
            return self._parse_gradle(manifest_file, lines, ecosystem)
        elif basename == "vcpkg.json":
            return self._parse_vcpkg(manifest_file, lines, ecosystem)

        return []

    def _parse_requirements_txt(
        self, manifest_file: str, lines: list[str], ecosystem: str
    ) -> list[DependencyChange]:
        """Parse requirements.txt style: package==version."""
        deps: list[DependencyChange] = []
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            match = _RE_REQUIREMENTS_TXT.match(line)
            if match:
                deps.append(
                    DependencyChange(
                        manifest_file=manifest_file,
                        package=match.group(1),
                        version=match.group(2),
                        ecosystem=ecosystem,
                    )
                )
        return deps

    def _parse_json_deps(
        self, manifest_file: str, lines: list[str], ecosystem: str
    ) -> list[DependencyChange]:
        """Parse package.json / package-lock.json style dependencies."""
        deps: list[DependencyChange] = []
        for line in lines:
            match = _RE_JSON_DEPENDENCY.search(line)
            if match:
                package = match.group(1).strip()
                version = match.group(2).strip()
                # Skip keys that are not package names
                if package in (
                    "name",
                    "version",
                    "description",
                    "main",
                    "scripts",
                    "license",
                    "repository",
                    "dependencies",
                    "devDependencies",
                    "peerDependencies",
                ):
                    continue
                deps.append(
                    DependencyChange(
                        manifest_file=manifest_file,
                        package=package,
                        version=version,
                        ecosystem=ecosystem,
                    )
                )
        return deps

    def _parse_yarn_lock(
        self, manifest_file: str, lines: list[str], ecosystem: str
    ) -> list[DependencyChange]:
        """Parse yarn.lock: pkg@version: resolved lines."""
        deps: list[DependencyChange] = []
        # yarn.lock format: "pkg@^version":
        yarn_re = re.compile(r'^"?([^@"]+)@[^"]*"?:?\s*$')
        version_re = re.compile(r'^\s+version\s+"([^"]+)"')
        current_pkg: str | None = None

        for line in lines:
            pkg_match = yarn_re.match(line)
            if pkg_match:
                current_pkg = pkg_match.group(1)
                continue
            if current_pkg:
                ver_match = version_re.match(line)
                if ver_match:
                    deps.append(
                        DependencyChange(
                            manifest_file=manifest_file,
                            package=current_pkg,
                            version=ver_match.group(1),
                            ecosystem=ecosystem,
                        )
                    )
                    current_pkg = None
        return deps

    def _parse_toml_style(
        self, manifest_file: str, lines: list[str], ecosystem: str
    ) -> list[DependencyChange]:
        """Parse Pipfile / pyproject.toml style: package = "version"."""
        deps: list[DependencyChange] = []
        toml_re = re.compile(
            r"""^["\']?([A-Za-z0-9][\w.\-]*)["\']?\s*=\s*["\']([^"\']+)["\']"""
        )
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("["):
                continue
            match = toml_re.match(line)
            if match:
                pkg = match.group(1)
                ver = match.group(2)
                # Skip common TOML keys that aren't packages
                if pkg in (
                    "name",
                    "version",
                    "description",
                    "python",
                    "python_requires",
                    "requires-python",
                ):
                    continue
                # Try to extract a version number
                ver_num = re.search(r"[\d]+[\d.]*", ver)
                if ver_num:
                    deps.append(
                        DependencyChange(
                            manifest_file=manifest_file,
                            package=pkg,
                            version=ver_num.group(0),
                            ecosystem=ecosystem,
                        )
                    )
        return deps

    def _parse_lock_json_style(
        self, manifest_file: str, lines: list[str], ecosystem: str
    ) -> list[DependencyChange]:
        """Parse Pipfile.lock / poetry.lock JSON-like style."""
        deps: list[DependencyChange] = []
        # Pipfile.lock: "package_name": { ... "version": "==x.y.z" }
        # poetry.lock: name = "package"\n version = "x.y.z"
        name_re = re.compile(r'["\']?name["\']?\s*[:=]\s*["\']([^"\']+)["\']')
        version_re = re.compile(r'["\']?version["\']?\s*[:=]\s*["\']([^"\']+)["\']')

        current_name: str | None = None
        for line in lines:
            nm = name_re.search(line)
            if nm:
                current_name = nm.group(1)
                continue
            vm = version_re.search(line)
            if vm and current_name:
                version = vm.group(1).lstrip("=")
                deps.append(
                    DependencyChange(
                        manifest_file=manifest_file,
                        package=current_name,
                        version=version,
                        ecosystem=ecosystem,
                    )
                )
                current_name = None
            elif vm and not current_name:
                # version without a name context — skip
                pass
        return deps

    def _parse_cargo_toml(
        self, manifest_file: str, lines: list[str], ecosystem: str
    ) -> list[DependencyChange]:
        """Parse Cargo.toml dependencies."""
        deps: list[DependencyChange] = []
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("["):
                continue
            match = _RE_CARGO_TOML.match(line)
            if match:
                pkg = match.group(1)
                ver = match.group(2) or match.group(3)
                if ver and pkg not in ("name", "version", "edition", "rust-version"):
                    deps.append(
                        DependencyChange(
                            manifest_file=manifest_file,
                            package=pkg,
                            version=ver,
                            ecosystem=ecosystem,
                        )
                    )
        return deps

    def _parse_cargo_lock(
        self, manifest_file: str, lines: list[str], ecosystem: str
    ) -> list[DependencyChange]:
        """Parse Cargo.lock: [[package]] name = "x" version = "y"."""
        deps: list[DependencyChange] = []
        name_re = re.compile(r'^name\s*=\s*"([^"]+)"')
        version_re = re.compile(r'^version\s*=\s*"([^"]+)"')
        current_name: str | None = None

        for line in lines:
            line = line.strip()
            nm = name_re.match(line)
            if nm:
                current_name = nm.group(1)
                continue
            vm = version_re.match(line)
            if vm and current_name:
                deps.append(
                    DependencyChange(
                        manifest_file=manifest_file,
                        package=current_name,
                        version=vm.group(1),
                        ecosystem=ecosystem,
                    )
                )
                current_name = None
        return deps

    def _parse_go_mod(
        self, manifest_file: str, lines: list[str], ecosystem: str
    ) -> list[DependencyChange]:
        """Parse go.mod / go.sum dependencies."""
        deps: list[DependencyChange] = []
        for line in lines:
            line = line.strip()
            if not line or line.startswith("//") or line.startswith("module"):
                continue
            # Remove "require " prefix if present
            if line.startswith("require "):
                line = line[len("require "):]
            # Remove parentheses
            if line in ("(", ")"):
                continue
            match = _RE_GO_MOD.match(line)
            if match:
                module = match.group(1)
                version = match.group(2)
                deps.append(
                    DependencyChange(
                        manifest_file=manifest_file,
                        package=module,
                        version=version,
                        ecosystem=ecosystem,
                    )
                )
        return deps

    def _parse_pom_xml(
        self, manifest_file: str, lines: list[str], ecosystem: str
    ) -> list[DependencyChange]:
        """Parse pom.xml: extract artifactId + version pairs."""
        deps: list[DependencyChange] = []
        current_artifact: str | None = None

        for line in lines:
            art_match = _RE_POM_ARTIFACT.search(line)
            if art_match:
                current_artifact = art_match.group(1).strip()
                continue
            ver_match = _RE_POM_VERSION.search(line)
            if ver_match and current_artifact:
                deps.append(
                    DependencyChange(
                        manifest_file=manifest_file,
                        package=current_artifact,
                        version=ver_match.group(1).strip(),
                        ecosystem=ecosystem,
                    )
                )
                current_artifact = None
        return deps

    def _parse_gradle(
        self, manifest_file: str, lines: list[str], ecosystem: str
    ) -> list[DependencyChange]:
        """Parse build.gradle dependencies."""
        deps: list[DependencyChange] = []
        for line in lines:
            match = _RE_GRADLE.search(line)
            if match:
                group = match.group(1)
                name = match.group(2)
                version = match.group(3)
                deps.append(
                    DependencyChange(
                        manifest_file=manifest_file,
                        package=f"{group}:{name}",
                        version=version,
                        ecosystem=ecosystem,
                    )
                )
        return deps

    def _parse_vcpkg(
        self, manifest_file: str, lines: list[str], ecosystem: str
    ) -> list[DependencyChange]:
        """Parse vcpkg.json dependencies."""
        deps: list[DependencyChange] = []
        current_name: str | None = None

        for line in lines:
            nm = _RE_VCPKG_NAME.search(line)
            if nm:
                current_name = nm.group(1)
                continue
            vm = _RE_VCPKG_VERSION.search(line)
            if vm and current_name:
                deps.append(
                    DependencyChange(
                        manifest_file=manifest_file,
                        package=current_name,
                        version=vm.group(1),
                        ecosystem=ecosystem,
                    )
                )
                current_name = None
        return deps
