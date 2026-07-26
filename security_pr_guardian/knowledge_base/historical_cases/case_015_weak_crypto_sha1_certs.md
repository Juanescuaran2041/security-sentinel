# Case: SHA-1 collision en certificados (SHAttered, 2017)

## CVE

N/A (ataque criptográfico demostrado)

## CWE asociado

CWE-327

## Descripción

Google y CWI Amsterdam demostraron la primera colisión práctica de SHA-1 en 2017 (proyecto SHAttered). Dos PDFs con contenido diferente pero mismo hash SHA-1 — probando que SHA-1 no es collision-resistant para firmas digitales ni verificación de integridad.

## Código vulnerable

```python
import hashlib

# Verificación de integridad con SHA-1 (no collision-resistant)
def verify_file_integrity(file_data: bytes, expected_hash: str) -> bool:
    actual = hashlib.sha1(file_data).hexdigest()
    return actual == expected_hash

# HMAC con SHA-1 (menos problemático que hash puro, pero deprecated)
import hmac
mac = hmac.new(key, data, hashlib.sha1).hexdigest()

# Firma de commits/tags con SHA-1 (Git lo usaba)
```

## Código corregido

```python
import hashlib

# SHA-256 para integridad
def verify_file_integrity(file_data: bytes, expected_hash: str) -> bool:
    actual = hashlib.sha256(file_data).hexdigest()
    return actual == expected_hash

# BLAKE2b - más rápido que SHA-256, igualmente seguro
def fast_hash(data: bytes) -> str:
    return hashlib.blake2b(data).hexdigest()

# HMAC con SHA-256
import hmac
mac = hmac.new(key, data, hashlib.sha256).hexdigest()
```

## Contexto

El costo de la colisión fue ~$110,000 en compute (GPU). Esto está al alcance de atacantes con recursos (estados, crimen organizado). Git migró de SHA-1 a SHA-256. Todos los CAs dejaron de emitir certificados SHA-1 desde 2017. Si tu código usa SHA-1 para cualquier propósito de seguridad (no solo passwords), necesita migrar.

## Referencia

- https://shattered.io/
- https://cwe.mitre.org/data/definitions/327.html
