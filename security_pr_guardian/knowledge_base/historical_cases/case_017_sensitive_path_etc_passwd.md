# Case: Path Traversal a /etc/passwd en aplicación web (CVE-2021-41773)

## CVE

CVE-2021-41773

## CWE asociado

CWE-552

## Descripción

Apache HTTP Server 2.4.49 tenía una vulnerabilidad de path traversal que permitía a atacantes acceder a archivos fuera del document root usando sequences de URL encoding (`%2e` para `.`). Permitía leer `/etc/passwd` y otros archivos sensibles del sistema.

## Código vulnerable

```python
# Patrón equivalente en Python: servir archivos sin validar path
from flask import Flask, send_file, request

app = Flask(__name__)

@app.route("/download")
def download():
    filename = request.args.get("file")
    # Sin validación — permite ../../etc/passwd
    return send_file(f"/var/www/files/{filename}")
```

## Código corregido

```python
from flask import Flask, send_file, request, abort
from pathlib import Path

app = Flask(__name__)
BASE_DIR = Path("/var/www/files").resolve()

@app.route("/download")
def download():
    filename = request.args.get("file", "")
    # Resolver path completo y verificar que está dentro de BASE_DIR
    requested = (BASE_DIR / filename).resolve()
    if not str(requested).startswith(str(BASE_DIR)):
        abort(403)  # Path traversal attempt
    if not requested.is_file():
        abort(404)
    return send_file(requested)
```

## Contexto

CVE-2021-41773 fue explotado activamente en the wild. El payload era simplemente: `GET /cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd`. Si mod_cgi estaba habilitado, también permitía RCE. El fix de Apache normalizaba la URL antes de resolver el path.

## Referencia

- https://nvd.nist.gov/vuln/detail/CVE-2021-41773
- https://httpd.apache.org/security/vulnerabilities_24.html
