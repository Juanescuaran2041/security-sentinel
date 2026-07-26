# False Positive: SHA-1 usado para compatibilidad con Git o legacy checksums

## Patrón que dispara el detector

```python
hashlib.sha1(data).hexdigest()
```

## CWE reportado

CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)

## Por qué NO es vulnerable en estos contextos

SHA-1 tiene colisiones demostradas y no debe usarse para firmas digitales ni integridad adversarial. Pero hay casos donde se usa por compatibilidad o propósito no-criptográfico:

- **Compatibilidad con Git**: Git usa SHA-1 para object IDs — código que interactúa con Git necesita SHA-1
- **Verificación de checksums legacy**: comparar contra hashes ya publicados en SHA-1 (verificar descarga)
- **Fingerprinting no-adversarial**: similar a MD5, identificar contenido sin contexto de seguridad
- **APIs externas que requieren SHA-1**: algunas APIs legacy exigen firma SHA-1 (webhooks de GitHub v1)

## Criterio para descartar como falso positivo

Si SHA-1 se usa para:
- **Interacción con Git** (calcular object IDs, tree hashes)
- **Verificar checksums existentes** que ya fueron publicados en SHA-1
- **Compatibilidad con APIs** que requieren SHA-1 (y no hay alternativa)
- **Fingerprinting no-sensible** (deduplicación, cache)

→ **Disposición**: no explotable, severidad LOW/INFO

## Criterio para CONFIRMAR como verdadero positivo

Si SHA-1 se usa para:
- **Almacenar contraseñas** (peor si es sin salt)
- **Firmar datos** para verificación de integridad adversarial
- **Generar tokens** de autenticación o sesión
- **HMAC** en contexto donde SHA-256 está disponible
- **Certificados o TLS** (todos los CAs dejaron SHA-1)

→ **Disposición**: explotable, severidad MEDIUM/HIGH

## Ejemplo de código seguro (falso positivo)

```python
import hashlib

# Calcular Git blob hash — requiere SHA-1 por protocolo Git
def git_blob_hash(content: bytes) -> str:
    header = f"blob {len(content)}\0".encode()
    return hashlib.sha1(header + content).hexdigest()

# Verificar checksum de descarga publicado en SHA-1
expected_sha1 = "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"
actual = hashlib.sha1(downloaded_file).hexdigest()
assert actual == expected_sha1
```

## Ejemplo de código vulnerable (verdadero positivo)

```python
# SHA-1 para passwords — VULNERABLE
password_hash = hashlib.sha1(password.encode()).hexdigest()

# SHA-1 para firma de JWT custom — VULNERABLE
signature = hashlib.sha1(payload + secret).hexdigest()
```
