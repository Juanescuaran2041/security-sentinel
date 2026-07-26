"""Tests unitarios del DiffParser.

Verifica:
- Detección correcta de manifiestos
- Extracción de dependencias modificadas
- Truncación a 10 000 líneas con diff_truncated=True
- Sin análisis CVE cuando no hay manifiestos
"""

import os
from pathlib import Path

import pytest

from security_pr_guardian.core.diff_parser import DiffParser, DiffParseResult

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _load_fixture(name: str) -> str:
    """Load a diff fixture file."""
    return (FIXTURES_DIR / name).read_text(encoding="utf-8")


class TestDiffParserManifestDetection:
    """Tests para la detección de manifiestos de dependencias."""

    def test_detects_requirements_txt(self) -> None:
        """Detecta requirements.txt como manifiesto."""
        diff = _load_fixture("manifest_changes.diff")
        parser = DiffParser()
        result = parser.parse(diff)

        assert "requirements.txt" in result.manifest_files

    def test_detects_package_json(self) -> None:
        """Detecta package.json como manifiesto."""
        diff = _load_fixture("manifest_changes.diff")
        parser = DiffParser()
        result = parser.parse(diff)

        assert "package.json" in result.manifest_files

    def test_no_manifests_in_clean_code_diff(self) -> None:
        """No detecta manifiestos en un diff sin archivos de dependencias."""
        diff = _load_fixture("clean_pr.diff")
        parser = DiffParser()
        result = parser.parse(diff)

        assert result.manifest_files == []

    def test_detects_all_canonical_manifests(self) -> None:
        """Detecta todos los manifiestos canónicos cuando están en el diff."""
        manifests = [
            "package.json",
            "requirements.txt",
            "Pipfile",
            "Pipfile.lock",
            "pyproject.toml",
            "poetry.lock",
            "Cargo.toml",
            "Cargo.lock",
            "go.mod",
            "go.sum",
            "pom.xml",
            "build.gradle",
            "vcpkg.json",
            "package-lock.json",
            "yarn.lock",
        ]

        # Build a synthetic diff with all manifests
        lines = []
        for m in manifests:
            lines.append(f"diff --git a/{m} b/{m}")
            lines.append(f"--- a/{m}")
            lines.append(f"+++ b/{m}")
            lines.append("@@ -0,0 +1,1 @@")
            lines.append("+# placeholder")

        diff = "\n".join(lines)
        parser = DiffParser()
        result = parser.parse(diff)

        for m in manifests:
            assert m in result.manifest_files, f"Expected {m} to be detected"

    def test_manifest_with_subdirectory_path(self) -> None:
        """Detecta manifiestos incluso si tienen subdirectorio en la ruta."""
        diff = (
            "diff --git a/backend/requirements.txt b/backend/requirements.txt\n"
            "--- a/backend/requirements.txt\n"
            "+++ b/backend/requirements.txt\n"
            "@@ -0,0 +1,2 @@\n"
            "+flask==2.0.0\n"
            "+requests==2.28.0\n"
        )
        parser = DiffParser()
        result = parser.parse(diff)

        assert "backend/requirements.txt" in result.manifest_files

    def test_non_manifest_files_not_detected(self) -> None:
        """Archivos que no son manifiestos no se detectan como tales."""
        diff = (
            "diff --git a/src/main.py b/src/main.py\n"
            "--- a/src/main.py\n"
            "+++ b/src/main.py\n"
            "@@ -1,1 +1,2 @@\n"
            "+import os\n"
        )
        parser = DiffParser()
        result = parser.parse(diff)

        assert result.manifest_files == []


class TestDiffParserDependencyExtraction:
    """Tests para la extracción de cambios de dependencias."""

    def test_extracts_requirements_txt_dependencies(self) -> None:
        """Extrae dependencias de requirements.txt correctamente."""
        diff = _load_fixture("manifest_changes.diff")
        parser = DiffParser()
        result = parser.parse(diff)

        # Should detect django, pyyaml, cryptography from requirements.txt
        req_deps = [
            d for d in result.dependency_changes if d.manifest_file == "requirements.txt"
        ]
        packages = {d.package for d in req_deps}

        assert "django" in packages
        assert "pyyaml" in packages
        assert "cryptography" in packages

    def test_extracts_package_json_dependencies(self) -> None:
        """Extrae dependencias de package.json correctamente."""
        diff = _load_fixture("manifest_changes.diff")
        parser = DiffParser()
        result = parser.parse(diff)

        json_deps = [
            d for d in result.dependency_changes if d.manifest_file == "package.json"
        ]
        packages = {d.package for d in json_deps}

        assert "axios" in packages
        assert "jsonwebtoken" in packages

    def test_correct_ecosystem_for_requirements_txt(self) -> None:
        """Ecosistema es PyPI para requirements.txt."""
        diff = _load_fixture("manifest_changes.diff")
        parser = DiffParser()
        result = parser.parse(diff)

        req_deps = [
            d for d in result.dependency_changes if d.manifest_file == "requirements.txt"
        ]
        for dep in req_deps:
            assert dep.ecosystem == "PyPI"

    def test_correct_ecosystem_for_package_json(self) -> None:
        """Ecosistema es npm para package.json."""
        diff = _load_fixture("manifest_changes.diff")
        parser = DiffParser()
        result = parser.parse(diff)

        json_deps = [
            d for d in result.dependency_changes if d.manifest_file == "package.json"
        ]
        for dep in json_deps:
            assert dep.ecosystem == "npm"

    def test_extracts_versions_correctly(self) -> None:
        """Las versiones se extraen correctamente."""
        diff = _load_fixture("manifest_changes.diff")
        parser = DiffParser()
        result = parser.parse(diff)

        req_deps = {
            d.package: d.version
            for d in result.dependency_changes
            if d.manifest_file == "requirements.txt"
        }

        assert req_deps.get("django") == "4.2.0"
        assert req_deps.get("pyyaml") == "6.0.1"
        assert req_deps.get("cryptography") == "41.0.0"

    def test_no_dependencies_when_no_manifests(self) -> None:
        """Sin dependencias cuando no hay manifiestos en el diff."""
        diff = _load_fixture("clean_pr.diff")
        parser = DiffParser()
        result = parser.parse(diff)

        assert result.dependency_changes == []

    def test_go_mod_dependencies(self) -> None:
        """Extrae dependencias de go.mod."""
        diff = (
            "diff --git a/go.mod b/go.mod\n"
            "--- a/go.mod\n"
            "+++ b/go.mod\n"
            "@@ -3,3 +3,5 @@\n"
            " module example.com/myapp\n"
            " \n"
            "+github.com/gin-gonic/gin v1.9.1\n"
            "+golang.org/x/crypto v0.14.0\n"
        )
        parser = DiffParser()
        result = parser.parse(diff)

        assert "go.mod" in result.manifest_files
        packages = {d.package for d in result.dependency_changes}
        assert "github.com/gin-gonic/gin" in packages
        assert "golang.org/x/crypto" in packages

    def test_cargo_toml_dependencies(self) -> None:
        """Extrae dependencias de Cargo.toml."""
        diff = (
            "diff --git a/Cargo.toml b/Cargo.toml\n"
            "--- a/Cargo.toml\n"
            "+++ b/Cargo.toml\n"
            "@@ -5,2 +5,4 @@\n"
            " [dependencies]\n"
            '+serde = "1.0.188"\n'
            '+tokio = { version = "1.32.0", features = ["full"] }\n'
        )
        parser = DiffParser()
        result = parser.parse(diff)

        assert "Cargo.toml" in result.manifest_files
        packages = {d.package: d.version for d in result.dependency_changes}
        assert packages.get("serde") == "1.0.188"
        assert packages.get("tokio") == "1.32.0"

    def test_pom_xml_dependencies(self) -> None:
        """Extrae dependencias de pom.xml."""
        diff = (
            "diff --git a/pom.xml b/pom.xml\n"
            "--- a/pom.xml\n"
            "+++ b/pom.xml\n"
            "@@ -10,2 +10,6 @@\n"
            "+    <artifactId>spring-boot-starter-web</artifactId>\n"
            "+    <version>3.1.0</version>\n"
            "+    <artifactId>jackson-databind</artifactId>\n"
            "+    <version>2.15.2</version>\n"
        )
        parser = DiffParser()
        result = parser.parse(diff)

        assert "pom.xml" in result.manifest_files
        packages = {d.package: d.version for d in result.dependency_changes}
        assert packages.get("spring-boot-starter-web") == "3.1.0"
        assert packages.get("jackson-databind") == "2.15.2"

    def test_build_gradle_dependencies(self) -> None:
        """Extrae dependencias de build.gradle."""
        diff = (
            "diff --git a/build.gradle b/build.gradle\n"
            "--- a/build.gradle\n"
            "+++ b/build.gradle\n"
            "@@ -5,2 +5,4 @@\n"
            "+    implementation 'org.springframework.boot:spring-boot-starter:3.1.0'\n"
            "+    testImplementation 'junit:junit:4.13.2'\n"
        )
        parser = DiffParser()
        result = parser.parse(diff)

        assert "build.gradle" in result.manifest_files
        packages = {d.package: d.version for d in result.dependency_changes}
        assert packages.get("org.springframework.boot:spring-boot-starter") == "3.1.0"
        assert packages.get("junit:junit") == "4.13.2"


class TestDiffParserTruncation:
    """Tests para la truncación de diffs grandes."""

    def test_truncation_at_10000_lines(self) -> None:
        """El diff se trunca a 10 000 líneas añadidas."""
        # Build a diff with more than 10000 added lines
        lines = [
            "diff --git a/big_file.py b/big_file.py",
            "--- /dev/null",
            "+++ b/big_file.py",
            "@@ -0,0 +1,12000 @@",
        ]
        for i in range(12_000):
            lines.append(f"+line_{i}")

        diff = "\n".join(lines)
        parser = DiffParser(max_diff_lines=10_000)
        result = parser.parse(diff)

        assert result.diff_truncated is True
        assert len(result.added_lines) == 10_000

    def test_no_truncation_below_limit(self) -> None:
        """Sin truncación cuando el diff tiene menos de 10 000 líneas."""
        lines = [
            "diff --git a/small_file.py b/small_file.py",
            "--- /dev/null",
            "+++ b/small_file.py",
            "@@ -0,0 +1,100 @@",
        ]
        for i in range(100):
            lines.append(f"+line_{i}")

        diff = "\n".join(lines)
        parser = DiffParser(max_diff_lines=10_000)
        result = parser.parse(diff)

        assert result.diff_truncated is False
        assert len(result.added_lines) == 100

    def test_exactly_at_limit_not_truncated(self) -> None:
        """Exactamente en el límite no se trunca."""
        lines = [
            "diff --git a/exact.py b/exact.py",
            "--- /dev/null",
            "+++ b/exact.py",
            "@@ -0,0 +1,10000 @@",
        ]
        for i in range(10_000):
            lines.append(f"+line_{i}")

        diff = "\n".join(lines)
        parser = DiffParser(max_diff_lines=10_000)
        result = parser.parse(diff)

        assert result.diff_truncated is False
        assert len(result.added_lines) == 10_000

    def test_truncation_with_large_pr_fixture(self) -> None:
        """El fixture large_pr.diff se trunca correctamente."""
        diff = _load_fixture("large_pr.diff")
        parser = DiffParser(max_diff_lines=10_000)
        result = parser.parse(diff)

        # large_pr.diff has 10200 added lines
        assert result.diff_truncated is True
        assert len(result.added_lines) == 10_000

    def test_truncated_lines_not_in_results(self) -> None:
        """Las líneas truncadas no aparecen en los resultados."""
        lines = [
            "diff --git a/file.py b/file.py",
            "--- /dev/null",
            "+++ b/file.py",
            "@@ -0,0 +1,200 @@",
        ]
        for i in range(200):
            lines.append(f"+content_line_{i}")

        diff = "\n".join(lines)
        parser = DiffParser(max_diff_lines=100)
        result = parser.parse(diff)

        assert result.diff_truncated is True
        assert len(result.added_lines) == 100
        # No line beyond the limit should appear
        max_line_num = max(pl.line_number for pl in result.added_lines)
        assert max_line_num <= 100

    def test_custom_max_diff_lines(self) -> None:
        """Se respeta un max_diff_lines personalizado."""
        lines = [
            "diff --git a/file.py b/file.py",
            "--- /dev/null",
            "+++ b/file.py",
            "@@ -0,0 +1,50 @@",
        ]
        for i in range(50):
            lines.append(f"+line_{i}")

        diff = "\n".join(lines)
        parser = DiffParser(max_diff_lines=25)
        result = parser.parse(diff)

        assert result.diff_truncated is True
        assert len(result.added_lines) == 25

    def test_truncate_diff_method(self) -> None:
        """El método truncate_diff retorna el diff cortado correctamente."""
        lines = [
            "diff --git a/file.py b/file.py",
            "--- /dev/null",
            "+++ b/file.py",
            "@@ -0,0 +1,50 @@",
        ]
        for i in range(50):
            lines.append(f"+line_{i}")

        diff = "\n".join(lines)
        parser = DiffParser(max_diff_lines=20)
        truncated_diff, was_truncated = parser.truncate_diff(diff)

        assert was_truncated is True
        # Count added lines in truncated diff
        added = [l for l in truncated_diff.splitlines() if l.startswith("+") and not l.startswith("+++")]
        assert len(added) == 20


class TestDiffParserAddedLines:
    """Tests para la extracción de líneas añadidas."""

    def test_extracts_added_lines_only(self) -> None:
        """Solo extrae líneas con prefijo '+'."""
        diff = (
            "diff --git a/file.py b/file.py\n"
            "--- a/file.py\n"
            "+++ b/file.py\n"
            "@@ -1,3 +1,5 @@\n"
            " existing_line\n"
            "+new_line_1\n"
            "+new_line_2\n"
            " another_existing\n"
            "-removed_line\n"
        )
        parser = DiffParser()
        result = parser.parse(diff)

        contents = [pl.content for pl in result.added_lines]
        assert "new_line_1" in contents
        assert "new_line_2" in contents
        assert "existing_line" not in contents
        assert "removed_line" not in contents

    def test_line_numbers_tracked_correctly(self) -> None:
        """Los números de línea se rastrean correctamente."""
        diff = (
            "diff --git a/file.py b/file.py\n"
            "--- a/file.py\n"
            "+++ b/file.py\n"
            "@@ -1,3 +5,4 @@\n"
            " context\n"
            "+added_at_6\n"
            " context2\n"
            "+added_at_8\n"
        )
        parser = DiffParser()
        result = parser.parse(diff)

        assert result.added_lines[0].line_number == 6
        assert result.added_lines[0].content == "added_at_6"
        assert result.added_lines[1].line_number == 8
        assert result.added_lines[1].content == "added_at_8"

    def test_multiple_files_parsed(self) -> None:
        """Múltiples archivos en el diff se parsean correctamente."""
        diff = (
            "diff --git a/file1.py b/file1.py\n"
            "--- a/file1.py\n"
            "+++ b/file1.py\n"
            "@@ -1,1 +1,2 @@\n"
            "+line_in_file1\n"
            "diff --git a/file2.py b/file2.py\n"
            "--- a/file2.py\n"
            "+++ b/file2.py\n"
            "@@ -1,1 +1,2 @@\n"
            "+line_in_file2\n"
        )
        parser = DiffParser()
        result = parser.parse(diff)

        files = {pl.file for pl in result.added_lines}
        assert "file1.py" in files
        assert "file2.py" in files

    def test_multiple_hunks_in_same_file(self) -> None:
        """Múltiples hunks en el mismo archivo se parsean correctamente."""
        diff = (
            "diff --git a/file.py b/file.py\n"
            "--- a/file.py\n"
            "+++ b/file.py\n"
            "@@ -1,2 +1,3 @@\n"
            " line1\n"
            "+added_at_2\n"
            " line2\n"
            "@@ -10,2 +11,3 @@\n"
            " line10\n"
            "+added_at_12\n"
            " line11\n"
        )
        parser = DiffParser()
        result = parser.parse(diff)

        assert result.added_lines[0].line_number == 2
        assert result.added_lines[1].line_number == 12


class TestDiffParserNoCVEWithoutManifests:
    """Tests para verificar que no hay análisis CVE sin manifiestos."""

    def test_no_dependency_changes_without_manifests(self) -> None:
        """Sin manifiestos no se generan cambios de dependencias."""
        diff = _load_fixture("cwe_89_sql_injection.diff")
        parser = DiffParser()
        result = parser.parse(diff)

        assert result.manifest_files == []
        assert result.dependency_changes == []

    def test_code_only_diff_has_empty_dependencies(self) -> None:
        """Un diff con solo código Python no genera dependencias."""
        diff = _load_fixture("clean_pr.diff")
        parser = DiffParser()
        result = parser.parse(diff)

        assert result.dependency_changes == []
