# Case: Exposición de claves SSH privadas en aplicación

## CVE

N/A (patrón de misconfiguration recurrente)

## CWE asociado

CWE-552

## Descripción

Aplicaciones que leen claves SSH privadas directamente del filesystem para conexiones automatizadas, exponiendo la ruta en el código y potencialmente la key en logs o errores. Si el código se ejecuta en un container o CI, la key queda embebida en la imagen o en artifacts.

## Código vulnerable

```python
import paramiko

# Referencia directa a clave SSH privada del filesystem
def connect_to_server(host: str):
    key = paramiko.RSAKey.from_private_key_file(
        "/home/deploy/.ssh/id_rsa"  # Path hardcodeado a key privada
    )
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # también inseguro
    client.connect(host, username='deploy', pkey=key)
    return client

# O peor: key embebida en el código
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA3...
-----END RSA PRIVATE KEY-----"""
```

## Código corregido

```python
import paramiko
import os
from io import StringIO

def connect_to_server(host: str):
    # Key inyectada via variable de entorno (sin file reference)
    key_str = os.environ["SSH_PRIVATE_KEY"]
    key = paramiko.RSAKey.from_private_key(StringIO(key_str))

    client = paramiko.SSHClient()
    # Verificar host key contra known_hosts
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    client.connect(host, username='deploy', pkey=key)
    return client

# En CI/CD: la key se inyecta como secret del runner
# En AWS: usar Systems Manager Session Manager en lugar de SSH
```

## Contexto

Las claves SSH en filesystem son un target primario en post-exploitation. Si un atacante logra lectura de archivos (via LFI, SSRF, o path traversal), `~/.ssh/id_rsa` es uno de los primeros archivos que intenta leer. Las keys deben inyectarse al runtime, nunca existir como archivos estáticos accesibles.

## Referencia

- https://cwe.mitre.org/data/definitions/552.html
- https://docs.github.com/en/actions/security-guides/encrypted-secrets
