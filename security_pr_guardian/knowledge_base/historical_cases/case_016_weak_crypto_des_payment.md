# Case: Cifrado DES en procesador de pagos

## CVE

N/A (patrón de compliance violation PCI-DSS)

## CWE asociado

CWE-327

## Descripción

Aplicación legacy de procesamiento de pagos usando DES (56-bit key) para cifrar datos de tarjetas de crédito. DES fue deprecado en 2005 y puede ser roto por fuerza bruta en horas con hardware moderno. Violación directa de PCI-DSS que requiere AES-128 mínimo.

## Código vulnerable

```python
from Crypto.Cipher import DES

# DES con key de 8 bytes (56 bits efectivos) — roto
key = b'12345678'
cipher = DES.new(key, DES.MODE_ECB)  # ECB mode + DES = doblemente inseguro
encrypted_card = cipher.encrypt(pad(card_number.encode(), 8))
```

## Código corregido

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# AES-256-GCM: cifrado autenticado con key de 256 bits
key = os.urandom(32)  # 256 bits
aesgcm = AESGCM(key)
nonce = os.urandom(12)  # 96-bit nonce para GCM
encrypted_card = aesgcm.encrypt(nonce, card_number.encode(), associated_data=b"payment")

# La key se almacena en AWS KMS o HSM, no en el código
```

## Contexto

DES tiene key space de 2^56 — crackeble en ~10 horas con FPGA. Triple-DES (3DES) fue el reemplazo temporal pero también está deprecated desde 2023 (NIST SP 800-131A Rev.2). AES-256 con GCM mode es el estándar actual para datos sensibles en reposo y tránsito.

## Referencia

- https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final
- https://cwe.mitre.org/data/definitions/327.html
