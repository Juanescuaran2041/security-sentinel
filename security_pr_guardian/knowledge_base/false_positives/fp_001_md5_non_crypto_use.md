# False Positive: hashlib.md5 usado para fingerprinting no-criptográfico

## Patrón que dispara el detector

```python
hashlib.md5(data).hexdigest()
hashlib.md5(file_content).digest()
```

## CWE reportado

CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)

## Por qué NO es vulnerable en estos contextos

MD5 solo es un problema de seguridad cuando se usa para propósitos criptográficos (integridad adversarial, firmas, passwords). Hay usos legítimos donde las propiedades criptográficas no importan:

- **Cache keys**: generar una key de caché basada en contenido
- **ETags HTTP**: fingerprint de contenido para cache de respuestas
- **Deduplicación**: identificar archivos duplicados en almacenamiento
- **Content-addressing**: nombrar blobs por su contenido (como Git internamente)
- **Checksums no-adversariales**: verificar corrupción accidental en transferencias internas

## Criterio para descartar como falso positivo

Si el hash MD5 se usa para:
- Generar cache keys o identificadores internos
- ETags de respuestas HTTP
- Deduplicación de contenido en storage
- Fingerprinting de archivos para comparación
- Identificadores no-sensibles (no passwords, no firmas, no tokens)

→ **Disposición**: no explotable, severidad INFO

## Criterio para CONFIRMAR como verdadero positivo

Si el hash MD5 se usa para:
- Almacenar contraseñas o secrets
- Verificar integridad en contexto adversarial (firmas digitales)
- HMAC o autenticación de mensajes
- Generar tokens de sesión o autenticación
- Comparar archivos donde un atacante podría crear colisiones

→ **Disposición**: explotable, severidad según contexto

## Ejemplo de código seguro (falso positivo)

```python
# Cache key — no es un problema de seguridad
import hashlib
def get_cache_key(query_params: dict) -> str:
    content = str(sorted(query_params.items())).encode()
    return f"cache:{hashlib.md5(content).hexdigest()}"

# ETag para HTTP caching
def compute_etag(response_body: bytes) -> str:
    return hashlib.md5(response_body).hexdigest()
```

## Ejemplo de código vulnerable (verdadero positivo)

```python
# Almacenamiento de password — SÍ es vulnerable
def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()  # VULNERABLE
```
