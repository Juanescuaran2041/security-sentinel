# Case: OS Command Injection vía subprocess en aplicación Flask

## CVE

CVE-2017-18342 (relacionado: PyYAML, pero el patrón aplica a subprocess)

## CWE asociado

CWE-78

## Descripción

Patrón común en aplicaciones web Python: uso de `subprocess.call()` o `os.system()` con `shell=True` concatenando input del request HTTP. Permite al atacante encadenar comandos con `;`, `&&`, `|`, o `$(...)`.

## Código vulnerable

```python
from flask import Flask, request
import subprocess

app = Flask(__name__)

@app.route("/ping")
def ping():
    host = request.args.get("host")
    # shell=True + input directo = RCE
    result = subprocess.check_output(f"ping -c 1 {host}", shell=True)
    return result.decode()
```

## Código corregido

```python
from flask import Flask, request
import subprocess
import ipaddress

app = Flask(__name__)

@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    # Validar que es una IP válida
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return "Invalid IP address", 400
    # Lista de argumentos sin shell=True
    result = subprocess.check_output(
        ["ping", "-c", "1", str(addr)],
        timeout=5
    )
    return result.decode()
```

## Contexto

El payload `; cat /etc/passwd` o `$(whoami)` inyectado en el parámetro `host` ejecuta comandos adicionales. Sin `shell=True` y con argumentos como lista, el input se pasa literalmente al binario sin interpretación del shell.

## Referencia

- https://owasp.org/www-community/attacks/Command_Injection
- https://cwe.mitre.org/data/definitions/78.html
