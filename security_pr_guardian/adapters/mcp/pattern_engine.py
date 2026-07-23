"""PatternEngine — Motor de detección de vulnerabilidades basado en regex.

Aplica reglas regex (una por CWE) sobre líneas añadidas (prefijo '+') de
diffs unificados. Agnóstico del lenguaje — sin AST, sin tree-sitter.

Cubre 7 CWEs: 89, 78, 79, 502, 798, 327, 552.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Pattern

from security_pr_guardian.core.models import (
    CandidateFinding,
    Severity,
    StaticAnalysisResult,
)


@dataclass(frozen=True)
class VulnerabilityRule:
    """Regla de detección de vulnerabilidad basada en regex."""

    cwe_id: str
    name: str
    tipo_vulnerabilidad: str
    pattern: Pattern[str]
    severidad_inicial: Severity
    description: str = ""


# ---------------------------------------------------------------------------
# Reglas de detección — una por CWE
# ---------------------------------------------------------------------------

_RULES: list[VulnerabilityRule] = [
    # CWE-89: SQL Injection — string formatting en keywords SQL
    VulnerabilityRule(
        cwe_id="CWE-89",
        name="SQL Injection",
        tipo_vulnerabilidad="Inyección SQL",
        pattern=re.compile(
            r"""(?ix)
            (?:
                # f-string con keyword SQL
                f['\"].*?\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|EXEC)\b.*?\{
                |
                # .format() con keyword SQL
                ['\"].*?\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|EXEC)\b.*?['\"]
                \s*\.format\s*\(
                |
                # %-formatting con keyword SQL
                ['\"].*?\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|EXEC)\b.*?%[sd].*?['\"]
                \s*%\s*[\(\w]
                |
                # Concatenación directa con keyword SQL
                ['\"].*?\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|EXEC)\b.*?['\"]
                \s*\+\s*\w
            )
            """,
        ),
        severidad_inicial=Severity.HIGH,
        description="Formateo de strings en keywords SQL sin parametrización",
    ),
    # CWE-78: OS Command Injection
    VulnerabilityRule(
        cwe_id="CWE-78",
        name="OS Command Injection",
        tipo_vulnerabilidad="Inyección de comandos OS",
        pattern=re.compile(
            r"""(?ix)
            (?:
                # os.system con variable
                os\.system\s*\(
                |
                # os.popen con variable
                os\.popen\s*\(
                |
                # subprocess con shell=True
                subprocess\.(?:call|run|Popen|check_output|check_call)\s*\(.*?shell\s*=\s*True
                |
                # commands.getoutput / getstatusoutput
                commands\.(?:getoutput|getstatusoutput)\s*\(
            )
            """,
        ),
        severidad_inicial=Severity.HIGH,
        description="os.system, subprocess con shell=True e input variable",
    ),
    # CWE-79: XSS — interpolación de variables sin escapar en HTML
    VulnerabilityRule(
        cwe_id="CWE-79",
        name="Cross-Site Scripting (XSS)",
        tipo_vulnerabilidad="XSS",
        pattern=re.compile(
            r"""(?ix)
            (?:
                # innerHTML assignment
                \.innerHTML\s*=
                |
                # document.write con variable
                document\.write\s*\(
                |
                # Jinja2 sin escapar
                \{\{\s*\w+.*?\s*\|\s*safe\s*\}\}
                |
                # f-string/format con etiquetas HTML
                (?:f['\"]|['\"].*?\.format)\s*.*?<\s*(?:script|div|span|p|a|img|iframe)\b
                |
                # render_template_string (Flask)
                render_template_string\s*\(
                |
                # Markup sin escapar
                Markup\s*\(.*?\{
                |
                # dangerouslySetInnerHTML (React)
                dangerouslySetInnerHTML
            )
            """,
        ),
        severidad_inicial=Severity.HIGH,
        description="Interpolación de variables sin escapar en respuestas HTML",
    ),
    # CWE-502: Insecure Deserialization
    VulnerabilityRule(
        cwe_id="CWE-502",
        name="Insecure Deserialization",
        tipo_vulnerabilidad="Deserialización insegura",
        pattern=re.compile(
            r"""(?ix)
            (?:
                # pickle.loads / pickle.load
                pickle\.loads?\s*\(
                |
                # yaml.load without Loader= (no comma means no kwargs)
                yaml\.load\s*\(\s*[^,)]+\s*\)
                |
                # yaml.unsafe_load
                yaml\.unsafe_load\s*\(
                |
                # eval()
                \beval\s*\(
                |
                # marshal.loads
                marshal\.loads?\s*\(
                |
                # shelve.open
                shelve\.open\s*\(
                |
                # jsonpickle.decode
                jsonpickle\.decode\s*\(
            )
            """,
        ),
        severidad_inicial=Severity.CRITICAL,
        description="pickle.loads, yaml.load sin Loader=, eval()",
    ),
    # CWE-798: Hardcoded Credentials
    VulnerabilityRule(
        cwe_id="CWE-798",
        name="Hardcoded Credentials",
        tipo_vulnerabilidad="Credenciales hardcodeadas",
        pattern=re.compile(
            r"""(?ix)
            (?:
                # Assignment to password/secret/api_key/token with string literal
                (?:password|passwd|secret|api_key|apikey|api_secret|token|auth_token|access_token|private_key)
                \s*=\s*
                ['\"][^'\"]{3,}['\"]
            )
            """,
        ),
        severidad_inicial=Severity.HIGH,
        description="Asignación a password/secret/api_key/token con literal de string",
    ),
    # CWE-327: Weak Cryptography
    VulnerabilityRule(
        cwe_id="CWE-327",
        name="Weak Cryptography",
        tipo_vulnerabilidad="Criptografía débil",
        pattern=re.compile(
            r"""(?ix)
            (?:
                # hashlib.md5 / hashlib.sha1
                hashlib\.(?:md5|sha1)\s*\(
                |
                # Direct md5( / sha1( calls
                \bmd5\s*\(
                |
                \bsha1\s*\(
                |
                # DES.new(
                DES\.new\s*\(
                |
                # Crypto.Cipher with DES
                Cipher\.DES
                |
                # MD5.new()
                MD5\.new\s*\(
                |
                # SHA.new() — SHA1
                \bSHA\.new\s*\(
            )
            """,
        ),
        severidad_inicial=Severity.MEDIUM,
        description="md5(, sha1(, DES.new(, hashlib.md5, hashlib.sha1",
    ),
    # CWE-552: Sensitive Path Reference
    VulnerabilityRule(
        cwe_id="CWE-552",
        name="Sensitive Path Reference",
        tipo_vulnerabilidad="Referencia a rutas sensibles",
        pattern=re.compile(
            r"""(?x)
            (?:
                /etc/passwd
                |
                /etc/shadow
                |
                /etc/sudoers
                |
                ~/\.ssh/
                |
                ~\/\.ssh\/
                |
                /\.ssh/
                |
                /etc/ssl/private
                |
                /proc/self/environ
                |
                \.pem['\"\s]
                |
                id_rsa
            )
            """,
        ),
        severidad_inicial=Severity.MEDIUM,
        description="Rutas absolutas con /etc/passwd, /etc/shadow, ~/.ssh/",
    ),
]


# ---------------------------------------------------------------------------
# Diff Parser helpers
# ---------------------------------------------------------------------------

_DIFF_FILE_HEADER = re.compile(r"^\+\+\+ b/(.+)$")
_HUNK_HEADER = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


class PatternEngine:
    """Motor de análisis estático basado en regex sobre diffs unificados.

    Analiza líneas añadidas (prefijo '+') del diff y aplica las reglas
    de vulnerabilidad definidas para los 7 CWEs objetivo.
    """

    def __init__(self, rules: list[VulnerabilityRule] | None = None) -> None:
        """Inicializa el engine con las reglas de detección.

        Args:
            rules: Lista de reglas a aplicar. Si es None, usa las 7 reglas
                   predefinidas.
        """
        self.rules = rules if rules is not None else _RULES

    def analyze(self, diff: str) -> StaticAnalysisResult:
        """Analiza un diff unificado en busca de patrones de vulnerabilidad.

        Args:
            diff: Diff unificado completo (formato git diff / GitHub PR diff).

        Returns:
            StaticAnalysisResult con hallazgos candidatos y errores parciales.
        """
        findings: list[CandidateFinding] = []
        errores_parciales: list[dict[str, str]] = []

        current_file: str | None = None
        current_line: int = 0

        for raw_line in diff.splitlines():
            # Detect file header: +++ b/path/to/file
            file_match = _DIFF_FILE_HEADER.match(raw_line)
            if file_match:
                current_file = file_match.group(1)
                current_line = 0
                continue

            # Detect hunk header: @@ -x,y +x,y @@
            hunk_match = _HUNK_HEADER.match(raw_line)
            if hunk_match:
                current_line = int(hunk_match.group(1))
                continue

            # Skip lines without a file context
            if current_file is None:
                continue

            # Only process added lines (prefix '+')
            if raw_line.startswith("+") and not raw_line.startswith("+++"):
                # Strip the '+' prefix for pattern matching
                code_line = raw_line[1:]

                try:
                    self._scan_line(
                        code_line=code_line,
                        archivo=current_file,
                        linea=current_line,
                        findings=findings,
                    )
                except Exception as exc:
                    errores_parciales.append(
                        {
                            "archivo": current_file,
                            "linea": str(current_line),
                            "error": str(exc),
                        }
                    )

                current_line += 1
            elif raw_line.startswith("-") and not raw_line.startswith("---"):
                # Deleted lines don't affect the new-file line counter
                pass
            else:
                # Context lines (no prefix) advance the line counter
                if not raw_line.startswith("---") and not raw_line.startswith("\\"):
                    current_line += 1

        return StaticAnalysisResult(
            findings=findings,
            errores_parciales=errores_parciales,
        )

    def _scan_line(
        self,
        code_line: str,
        archivo: str,
        linea: int,
        findings: list[CandidateFinding],
    ) -> None:
        """Aplica todas las reglas a una línea de código.

        Args:
            code_line: Línea de código (sin el prefijo '+').
            archivo: Ruta del archivo extraída del header del diff.
            linea: Número de línea en el archivo nuevo.
            findings: Lista donde se acumulan los hallazgos.
        """
        for rule in self.rules:
            match = rule.pattern.search(code_line)
            if match:
                fragmento = code_line.strip()[:500]
                findings.append(
                    CandidateFinding(
                        source="static",
                        tipo_vulnerabilidad=rule.tipo_vulnerabilidad,
                        archivo=archivo,
                        linea_inicio=linea,
                        linea_fin=linea,
                        fragmento_codigo=fragmento,
                        patron_detectado=rule.name,
                        cwe_id=rule.cwe_id,
                        severidad_inicial=rule.severidad_inicial,
                    )
                )
