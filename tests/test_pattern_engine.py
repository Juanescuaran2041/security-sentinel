"""Tests unitarios para PatternEngine."""

import pytest

from security_pr_guardian.adapters.mcp.pattern_engine import PatternEngine


class TestPatternEngineInstantiation:
    """Tests de instanciación básica."""

    def test_creates_with_default_rules(self):
        engine = PatternEngine()
        assert len(engine.rules) == 7

    def test_rule_cwe_ids(self):
        engine = PatternEngine()
        cwe_ids = [r.cwe_id for r in engine.rules]
        assert "CWE-89" in cwe_ids
        assert "CWE-78" in cwe_ids
        assert "CWE-79" in cwe_ids
        assert "CWE-502" in cwe_ids
        assert "CWE-798" in cwe_ids
        assert "CWE-327" in cwe_ids
        assert "CWE-552" in cwe_ids

    def test_creates_with_custom_rules(self):
        engine = PatternEngine(rules=[])
        assert len(engine.rules) == 0


class TestPatternEngineDiffParsing:
    """Tests de parsing del diff unificado."""

    def test_extracts_file_from_diff_header(self):
        diff = (
            "diff --git a/app.py b/app.py\n"
            "--- a/app.py\n"
            "+++ b/app.py\n"
            "@@ -1,3 +1,4 @@\n"
            " import os\n"
            "+os.system(cmd)\n"
        )
        engine = PatternEngine()
        result = engine.analyze(diff)
        assert len(result.findings) >= 1
        assert result.findings[0].archivo == "app.py"

    def test_tracks_line_numbers_from_hunk_header(self):
        diff = (
            "--- a/app.py\n"
            "+++ b/app.py\n"
            "@@ -10,3 +15,4 @@ def foo():\n"
            " context\n"
            "+os.system(cmd)\n"
        )
        engine = PatternEngine()
        result = engine.analyze(diff)
        assert len(result.findings) >= 1
        # Line starts at 15 (hunk), +1 for context line = 16
        assert result.findings[0].linea_inicio == 16

    def test_only_scans_added_lines(self):
        diff = (
            "--- a/app.py\n"
            "+++ b/app.py\n"
            "@@ -1,3 +1,3 @@\n"
            "-os.system(old_cmd)\n"
            "+print('safe line')\n"
            " import os\n"
        )
        engine = PatternEngine()
        result = engine.analyze(diff)
        # The removed line has os.system but should NOT be scanned
        assert len(result.findings) == 0

    def test_empty_diff_returns_no_findings(self):
        engine = PatternEngine()
        result = engine.analyze("")
        assert len(result.findings) == 0
        assert len(result.errores_parciales) == 0

    def test_multiple_files_in_diff(self):
        diff = (
            "--- a/file1.py\n"
            "+++ b/file1.py\n"
            "@@ -1,2 +1,3 @@\n"
            " import os\n"
            "+os.system(cmd)\n"
            "--- a/file2.py\n"
            "+++ b/file2.py\n"
            "@@ -1,2 +1,3 @@\n"
            " import hashlib\n"
            "+hashlib.md5(data)\n"
        )
        engine = PatternEngine()
        result = engine.analyze(diff)
        files = {f.archivo for f in result.findings}
        assert "file1.py" in files
        assert "file2.py" in files


class TestCWE89SQLInjection:
    """Tests para detección de SQL Injection."""

    def test_detects_fstring_sql(self):
        diff = (
            "+++ b/db.py\n"
            "@@ -1,1 +1,2 @@\n"
            '+    query = f"SELECT * FROM users WHERE id = {user_id}"\n'
        )
        engine = PatternEngine()
        result = engine.analyze(diff)
        cwe_ids = [f.cwe_id for f in result.findings]
        assert "CWE-89" in cwe_ids

    def test_detects_format_sql(self):
        diff = (
            "+++ b/db.py\n"
            "@@ -1,1 +1,2 @@\n"
            '+    query = "DELETE FROM users WHERE id = {}".format(uid)\n'
        )
        engine = PatternEngine()
        result = engine.analyze(diff)
        cwe_ids = [f.cwe_id for f in result.findings]
        assert "CWE-89" in cwe_ids

    def test_detects_percent_format_sql(self):
        diff = (
            "+++ b/db.py\n"
            "@@ -1,1 +1,2 @@\n"
            "+    query = \"SELECT * FROM table WHERE name = '%s'\" % (name)\n"
        )
        engine = PatternEngine()
        result = engine.analyze(diff)
        cwe_ids = [f.cwe_id for f in result.findings]
        assert "CWE-89" in cwe_ids

    def test_detects_concatenation_sql(self):
        diff = (
            "+++ b/db.py\n"
            "@@ -1,1 +1,2 @@\n"
            '+    query = "SELECT * FROM users WHERE id = " + user_input\n'
        )
        engine = PatternEngine()
        result = engine.analyze(diff)
        cwe_ids = [f.cwe_id for f in result.findings]
        assert "CWE-89" in cwe_ids

    def test_no_false_positive_parameterized(self):
        diff = (
            "+++ b/db.py\n"
            "@@ -1,1 +1,2 @@\n"
            "+    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))\n"
        )
        engine = PatternEngine()
        result = engine.analyze(diff)
        cwe_ids = [f.cwe_id for f in result.findings]
        assert "CWE-89" not in cwe_ids


class TestCWE78OSCommandInjection:
    """Tests para detección de OS Command Injection."""

    def test_detects_os_system(self):
        diff = (
            "+++ b/util.py\n"
            "@@ -1,1 +1,2 @@\n"
            "+    os.system(f'rm {path}')\n"
        )
        engine = PatternEngine()
        result = engine.analyze(diff)
        cwe_ids = [f.cwe_id for f in result.findings]
        assert "CWE-78" in cwe_ids

    def test_detects_subprocess_shell_true(self):
        diff = (
            "+++ b/util.py\n"
            "@@ -1,1 +1,2 @@\n"
            "+    subprocess.run(cmd, shell=True)\n"
        )
        engine = PatternEngine()
        result = engine.analyze(diff)
        cwe_ids = [f.cwe_id for f in result.findings]
        assert "CWE-78" in cwe_ids

    def test_detects_os_popen(self):
        diff = (
            "+++ b/util.py\n"
            "@@ -1,1 +1,2 @@\n"
            "+    result = os.popen(command)\n"
        )
        engine = PatternEngine()
        result = engine.analyze(diff)
        cwe_ids = [f.cwe_id for f in result.findings]
        assert "CWE-78" in cwe_ids

    def test_no_false_positive_subprocess_list(self):
        diff = (
            "+++ b/util.py\n"
            "@@ -1,1 +1,2 @@\n"
            "+    subprocess.run(['ls', '-la'])\n"
        )
        engine = PatternEngine()
        result = engine.analyze(diff)
        cwe_ids = [f.cwe_id for f in result.findings]
        assert "CWE-78" not in cwe_ids


class TestCWE502InsecureDeserialization:
    """Tests para detección de Deserialización Insegura."""

    def test_detects_pickle_loads(self):
        diff = (
            "+++ b/ser.py\n"
            "@@ -1,1 +1,2 @@\n"
            "+    obj = pickle.loads(data)\n"
        )
        engine = PatternEngine()
        result = engine.analyze(diff)
        cwe_ids = [f.cwe_id for f in result.findings]
        assert "CWE-502" in cwe_ids

    def test_detects_yaml_load_no_loader(self):
        diff = (
            "+++ b/conf.py\n"
            "@@ -1,1 +1,2 @@\n"
            "+    config = yaml.load(content)\n"
        )
        engine = PatternEngine()
        result = engine.analyze(diff)
        cwe_ids = [f.cwe_id for f in result.findings]
        assert "CWE-502" in cwe_ids

    def test_detects_eval(self):
        diff = (
            "+++ b/dyn.py\n"
            "@@ -1,1 +1,2 @@\n"
            "+    result = eval(user_input)\n"
        )
        engine = PatternEngine()
        result = engine.analyze(diff)
        cwe_ids = [f.cwe_id for f in result.findings]
        assert "CWE-502" in cwe_ids

    def test_no_false_positive_yaml_safe_load(self):
        diff = (
            "+++ b/conf.py\n"
            "@@ -1,1 +1,2 @@\n"
            "+    config = yaml.safe_load(content)\n"
        )
        engine = PatternEngine()
        result = engine.analyze(diff)
        cwe_ids = [f.cwe_id for f in result.findings]
        assert "CWE-502" not in cwe_ids


class TestCWE798HardcodedCredentials:
    """Tests para detección de Credenciales Hardcodeadas."""

    def test_detects_password_assignment(self):
        diff = (
            "+++ b/config.py\n"
            "@@ -1,1 +1,2 @@\n"
            "+    password = 'my_secret_pass_123'\n"
        )
        engine = PatternEngine()
        result = engine.analyze(diff)
        cwe_ids = [f.cwe_id for f in result.findings]
        assert "CWE-798" in cwe_ids

    def test_detects_api_key_assignment(self):
        diff = (
            "+++ b/config.py\n"
            "@@ -1,1 +1,2 @@\n"
            '+    api_key = "sk-1234567890abcdef"\n'
        )
        engine = PatternEngine()
        result = engine.analyze(diff)
        cwe_ids = [f.cwe_id for f in result.findings]
        assert "CWE-798" in cwe_ids

    def test_detects_token_assignment(self):
        diff = (
            "+++ b/auth.py\n"
            "@@ -1,1 +1,2 @@\n"
            '+    token = "ghp_xxxxxxxxxxxx"\n'
        )
        engine = PatternEngine()
        result = engine.analyze(diff)
        cwe_ids = [f.cwe_id for f in result.findings]
        assert "CWE-798" in cwe_ids

    def test_no_false_positive_env_var(self):
        diff = (
            "+++ b/config.py\n"
            "@@ -1,1 +1,2 @@\n"
            "+    password = os.environ.get('PASSWORD')\n"
        )
        engine = PatternEngine()
        result = engine.analyze(diff)
        cwe_ids = [f.cwe_id for f in result.findings]
        assert "CWE-798" not in cwe_ids


class TestCWE327WeakCryptography:
    """Tests para detección de Criptografía Débil."""

    def test_detects_hashlib_md5(self):
        diff = (
            "+++ b/hash.py\n"
            "@@ -1,1 +1,2 @@\n"
            "+    digest = hashlib.md5(data)\n"
        )
        engine = PatternEngine()
        result = engine.analyze(diff)
        cwe_ids = [f.cwe_id for f in result.findings]
        assert "CWE-327" in cwe_ids

    def test_detects_hashlib_sha1(self):
        diff = (
            "+++ b/hash.py\n"
            "@@ -1,1 +1,2 @@\n"
            "+    digest = hashlib.sha1(data)\n"
        )
        engine = PatternEngine()
        result = engine.analyze(diff)
        cwe_ids = [f.cwe_id for f in result.findings]
        assert "CWE-327" in cwe_ids

    def test_detects_des_new(self):
        diff = (
            "+++ b/crypto.py\n"
            "@@ -1,1 +1,2 @@\n"
            "+    cipher = DES.new(key)\n"
        )
        engine = PatternEngine()
        result = engine.analyze(diff)
        cwe_ids = [f.cwe_id for f in result.findings]
        assert "CWE-327" in cwe_ids

    def test_no_false_positive_sha256(self):
        diff = (
            "+++ b/hash.py\n"
            "@@ -1,1 +1,2 @@\n"
            "+    digest = hashlib.sha256(data)\n"
        )
        engine = PatternEngine()
        result = engine.analyze(diff)
        cwe_ids = [f.cwe_id for f in result.findings]
        assert "CWE-327" not in cwe_ids


class TestCWE552SensitivePathReference:
    """Tests para detección de Referencia a Rutas Sensibles."""

    def test_detects_etc_passwd(self):
        diff = (
            "+++ b/read.py\n"
            "@@ -1,1 +1,2 @@\n"
            "+    with open('/etc/passwd') as f:\n"
        )
        engine = PatternEngine()
        result = engine.analyze(diff)
        cwe_ids = [f.cwe_id for f in result.findings]
        assert "CWE-552" in cwe_ids

    def test_detects_etc_shadow(self):
        diff = (
            "+++ b/read.py\n"
            "@@ -1,1 +1,2 @@\n"
            "+    path = '/etc/shadow'\n"
        )
        engine = PatternEngine()
        result = engine.analyze(diff)
        cwe_ids = [f.cwe_id for f in result.findings]
        assert "CWE-552" in cwe_ids

    def test_detects_ssh_dir(self):
        diff = (
            "+++ b/deploy.py\n"
            "@@ -1,1 +1,2 @@\n"
            "+    key_path = '~/.ssh/id_rsa'\n"
        )
        engine = PatternEngine()
        result = engine.analyze(diff)
        cwe_ids = [f.cwe_id for f in result.findings]
        assert "CWE-552" in cwe_ids

    def test_no_false_positive_normal_path(self):
        diff = (
            "+++ b/app.py\n"
            "@@ -1,1 +1,2 @@\n"
            "+    path = '/usr/local/bin/python'\n"
        )
        engine = PatternEngine()
        result = engine.analyze(diff)
        cwe_ids = [f.cwe_id for f in result.findings]
        assert "CWE-552" not in cwe_ids


class TestCWE79XSS:
    """Tests para detección de XSS."""

    def test_detects_innerhtml(self):
        diff = (
            "+++ b/app.js\n"
            "@@ -1,1 +1,2 @@\n"
            "+    element.innerHTML = userInput;\n"
        )
        engine = PatternEngine()
        result = engine.analyze(diff)
        cwe_ids = [f.cwe_id for f in result.findings]
        assert "CWE-79" in cwe_ids

    def test_detects_document_write(self):
        diff = (
            "+++ b/app.js\n"
            "@@ -1,1 +1,2 @@\n"
            "+    document.write(data);\n"
        )
        engine = PatternEngine()
        result = engine.analyze(diff)
        cwe_ids = [f.cwe_id for f in result.findings]
        assert "CWE-79" in cwe_ids

    def test_detects_dangerously_set_innerhtml(self):
        diff = (
            "+++ b/component.tsx\n"
            "@@ -1,1 +1,2 @@\n"
            "+    <div dangerouslySetInnerHTML={{__html: data}} />\n"
        )
        engine = PatternEngine()
        result = engine.analyze(diff)
        cwe_ids = [f.cwe_id for f in result.findings]
        assert "CWE-79" in cwe_ids

    def test_detects_render_template_string(self):
        diff = (
            "+++ b/views.py\n"
            "@@ -1,1 +1,2 @@\n"
            "+    return render_template_string(user_template)\n"
        )
        engine = PatternEngine()
        result = engine.analyze(diff)
        cwe_ids = [f.cwe_id for f in result.findings]
        assert "CWE-79" in cwe_ids


class TestFindingStructure:
    """Tests para verificar la estructura de los findings."""

    def test_finding_has_source_static(self):
        diff = (
            "+++ b/app.py\n"
            "@@ -1,1 +1,2 @@\n"
            "+    os.system(cmd)\n"
        )
        engine = PatternEngine()
        result = engine.analyze(diff)
        assert result.findings[0].source == "static"

    def test_finding_fragmento_max_500_chars(self):
        long_line = "x" * 600
        diff = (
            "+++ b/app.py\n"
            "@@ -1,1 +1,2 @@\n"
            f"+    os.system({long_line})\n"
        )
        engine = PatternEngine()
        result = engine.analyze(diff)
        assert len(result.findings[0].fragmento_codigo) <= 500

    def test_finding_has_correct_cwe_id(self):
        diff = (
            "+++ b/hash.py\n"
            "@@ -1,1 +1,2 @@\n"
            "+    hashlib.md5(data)\n"
        )
        engine = PatternEngine()
        result = engine.analyze(diff)
        assert result.findings[0].cwe_id == "CWE-327"

    def test_result_is_static_analysis_result(self):
        from security_pr_guardian.core.models import StaticAnalysisResult

        engine = PatternEngine()
        result = engine.analyze("")
        assert isinstance(result, StaticAnalysisResult)


class TestCleanDiff:
    """Tests para diff sin vulnerabilidades."""

    def test_clean_diff_no_findings(self):
        diff = (
            "--- a/app.py\n"
            "+++ b/app.py\n"
            "@@ -1,3 +1,5 @@\n"
            " import logging\n"
            "+\n"
            "+logger = logging.getLogger(__name__)\n"
            "+logger.info('Application started')\n"
            " \n"
        )
        engine = PatternEngine()
        result = engine.analyze(diff)
        assert len(result.findings) == 0


# ---------------------------------------------------------------------------
# Fixture-based tests — verifican PatternEngine contra archivos reales de diff
# ---------------------------------------------------------------------------
from pathlib import Path

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _load_fixture(name: str) -> str:
    """Carga un archivo fixture y devuelve su contenido."""
    return (FIXTURES_DIR / name).read_text(encoding="utf-8")


class TestPatternEngineFixtures:
    """Tests que verifican PatternEngine contra los fixtures de diff reales.

    Cada fixture vulnerable debe producir al menos 1 finding con el CWE
    esperado, y clean_pr.diff no debe generar ningún finding.
    """

    @pytest.fixture
    def engine(self) -> PatternEngine:
        return PatternEngine()

    # ---- CWE-89: SQL Injection ----
    def test_fixture_cwe_89_detects_sql_injection(self, engine: PatternEngine):
        diff = _load_fixture("cwe_89_sql_injection.diff")
        result = engine.analyze(diff)
        cwe_ids = [f.cwe_id for f in result.findings]
        assert "CWE-89" in cwe_ids, "CWE-89 fixture should detect SQL injection"
        assert len(result.findings) >= 1

    # ---- CWE-78: OS Command Injection ----
    def test_fixture_cwe_78_detects_os_command_injection(self, engine: PatternEngine):
        diff = _load_fixture("cwe_78_os_command.diff")
        result = engine.analyze(diff)
        cwe_ids = [f.cwe_id for f in result.findings]
        assert "CWE-78" in cwe_ids, "CWE-78 fixture should detect OS command injection"
        assert len(result.findings) >= 1

    # ---- CWE-79: XSS ----
    def test_fixture_cwe_79_detects_xss(self, engine: PatternEngine):
        diff = _load_fixture("cwe_79_xss.diff")
        result = engine.analyze(diff)
        cwe_ids = [f.cwe_id for f in result.findings]
        assert "CWE-79" in cwe_ids, "CWE-79 fixture should detect XSS"
        assert len(result.findings) >= 1

    # ---- CWE-502: Insecure Deserialization ----
    def test_fixture_cwe_502_detects_deserialization(self, engine: PatternEngine):
        diff = _load_fixture("cwe_502_deserialization.diff")
        result = engine.analyze(diff)
        cwe_ids = [f.cwe_id for f in result.findings]
        assert "CWE-502" in cwe_ids, "CWE-502 fixture should detect insecure deserialization"
        assert len(result.findings) >= 1

    # ---- CWE-798: Hardcoded Credentials ----
    def test_fixture_cwe_798_detects_hardcoded_creds(self, engine: PatternEngine):
        diff = _load_fixture("cwe_798_hardcoded_creds.diff")
        result = engine.analyze(diff)
        cwe_ids = [f.cwe_id for f in result.findings]
        assert "CWE-798" in cwe_ids, "CWE-798 fixture should detect hardcoded credentials"
        assert len(result.findings) >= 1

    # ---- CWE-327: Weak Cryptography ----
    def test_fixture_cwe_327_detects_weak_crypto(self, engine: PatternEngine):
        diff = _load_fixture("cwe_327_weak_crypto.diff")
        result = engine.analyze(diff)
        cwe_ids = [f.cwe_id for f in result.findings]
        assert "CWE-327" in cwe_ids, "CWE-327 fixture should detect weak cryptography"
        assert len(result.findings) >= 1

    # ---- CWE-552: Sensitive Path Reference ----
    def test_fixture_cwe_552_detects_sensitive_paths(self, engine: PatternEngine):
        diff = _load_fixture("cwe_552_sensitive_path.diff")
        result = engine.analyze(diff)
        cwe_ids = [f.cwe_id for f in result.findings]
        assert "CWE-552" in cwe_ids, "CWE-552 fixture should detect sensitive path references"
        assert len(result.findings) >= 1

    # ---- Clean PR: sin falsos positivos ----
    def test_fixture_clean_pr_no_findings(self, engine: PatternEngine):
        diff = _load_fixture("clean_pr.diff")
        result = engine.analyze(diff)
        assert len(result.findings) == 0, (
            f"clean_pr.diff should produce 0 findings, got {len(result.findings)}: "
            f"{[(f.cwe_id, f.archivo, f.fragmento_codigo[:60]) for f in result.findings]}"
        )


class TestPatternEngineFixturesParametrized:
    """Tests parametrizados para verificar detección en fixtures vulnerables."""

    @pytest.mark.parametrize(
        "fixture_file,expected_cwe",
        [
            ("cwe_89_sql_injection.diff", "CWE-89"),
            ("cwe_78_os_command.diff", "CWE-78"),
            ("cwe_79_xss.diff", "CWE-79"),
            ("cwe_502_deserialization.diff", "CWE-502"),
            ("cwe_798_hardcoded_creds.diff", "CWE-798"),
            ("cwe_327_weak_crypto.diff", "CWE-327"),
            ("cwe_552_sensitive_path.diff", "CWE-552"),
        ],
        ids=[
            "sql_injection",
            "os_command",
            "xss",
            "deserialization",
            "hardcoded_creds",
            "weak_crypto",
            "sensitive_path",
        ],
    )
    def test_vulnerable_fixture_detects_target_cwe(
        self, fixture_file: str, expected_cwe: str
    ):
        engine = PatternEngine()
        diff = _load_fixture(fixture_file)
        result = engine.analyze(diff)
        cwe_ids = [f.cwe_id for f in result.findings]
        assert expected_cwe in cwe_ids, (
            f"{fixture_file} should detect {expected_cwe}, "
            f"but got CWEs: {set(cwe_ids)}"
        )

    @pytest.mark.parametrize(
        "fixture_file,expected_cwe",
        [
            ("cwe_89_sql_injection.diff", "CWE-89"),
            ("cwe_78_os_command.diff", "CWE-78"),
            ("cwe_79_xss.diff", "CWE-79"),
            ("cwe_502_deserialization.diff", "CWE-502"),
            ("cwe_798_hardcoded_creds.diff", "CWE-798"),
            ("cwe_327_weak_crypto.diff", "CWE-327"),
            ("cwe_552_sensitive_path.diff", "CWE-552"),
        ],
        ids=[
            "sql_injection",
            "os_command",
            "xss",
            "deserialization",
            "hardcoded_creds",
            "weak_crypto",
            "sensitive_path",
        ],
    )
    def test_vulnerable_fixture_all_findings_from_target_cwe(
        self, fixture_file: str, expected_cwe: str
    ):
        """Verifica que la mayoría de findings correspondan al CWE objetivo."""
        engine = PatternEngine()
        diff = _load_fixture(fixture_file)
        result = engine.analyze(diff)
        target_findings = [f for f in result.findings if f.cwe_id == expected_cwe]
        # El CWE objetivo debe ser el predominante (al menos la mitad)
        assert len(target_findings) >= len(result.findings) // 2, (
            f"{fixture_file}: expected {expected_cwe} to be predominant, "
            f"got {len(target_findings)}/{len(result.findings)} findings for target CWE"
        )
