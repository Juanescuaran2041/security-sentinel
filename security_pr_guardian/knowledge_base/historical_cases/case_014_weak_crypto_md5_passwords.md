# Case: MD5 para almacenamiento de contraseñas (LinkedIn breach 2012)

## CVE

N/A (breach por hash débil)

## CWE asociado

CWE-327

## Descripción

En 2012, 6.5 millones de hashes de contraseñas de LinkedIn fueron publicados online. Usaban SHA-1 sin salt — crackeadas en horas. El patrón más común en código legacy es MD5 o SHA-1 para passwords, sin salt ni iteraciones.

## Código vulnerable

```python
import hashlib

# Almacenamiento de contraseña con MD5 (crackeable en segundos)
def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()

# SHA-1 sin salt (mejor que MD5 pero aún inseguro)
def hash_password_sha1(password: str) -> str:
    return hashlib.sha1(password.encode()).hexdigest()

# Verificación
stored_hash = get_from_db(username)
if hash_password(submitted_password) == stored_hash:
    login_success()
```

## Código corregido

```python
import bcrypt

# bcrypt: salt automático + key stretching (cost factor configurable)
def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))

def verify_password(password: str, stored_hash: bytes) -> bool:
    return bcrypt.checkpw(password.encode(), stored_hash)

# Alternativa: argon2 (ganador de PHC - Password Hashing Competition)
from argon2 import PasswordHasher
ph = PasswordHasher()
hash = ph.hash(password)
ph.verify(hash, password)  # raises VerifyMismatchError si falla
```

## Contexto

MD5 se crackea a ~10 billones de hashes/segundo en GPU moderna. SHA-1 a ~5 billones. bcrypt con cost=12 limita a ~200 hashes/segundo en la misma GPU. La diferencia es de ordenes de magnitud: un password de 8 chars toma segundos con MD5 y años con bcrypt.

## Referencia

- https://cwe.mitre.org/data/definitions/327.html
- https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
