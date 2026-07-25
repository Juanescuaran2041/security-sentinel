# Case: RCE via pickle en sesiones Redis (CVE-2020-13254 relacionado)

## CVE

CVE-2020-13254 (Django sessions con pickle)

## CWE asociado

CWE-502

## Descripción

Django antes de 2.2.13, 3.0.x antes de 3.0.7 usaba pickle por defecto para serializar sesiones almacenadas en backends como Redis, Memcached o DB. Si un atacante podía modificar datos de sesión (ej: via SSRF al Redis expuesto), podía lograr RCE.

## Código vulnerable

```python
# settings.py de Django
SESSION_ENGINE = 'django.contrib.sessions.backends.cache'
SESSION_SERIALIZER = 'django.contrib.sessions.serializers.PickleSerializer'
# ↑ Pickle como serializer de sesiones = RCE si el backend es accesible

# Patrón genérico inseguro:
import pickle, redis
r = redis.Redis()
data = r.get(f"session:{session_id}")
session = pickle.loads(data)  # si el atacante controla Redis → RCE
```

## Código corregido

```python
# settings.py - usar JSON serializer (seguro)
SESSION_SERIALIZER = 'django.contrib.sessions.serializers.JSONSerializer'

# Patrón genérico seguro:
import json, redis
r = redis.Redis()
data = r.get(f"session:{session_id}")
session = json.loads(data)  # JSON no ejecuta código

# Si necesitas objetos complejos, usar signing
from django.core.signing import Signer
signer = Signer()
session = json.loads(signer.unsign(data))
```

## Contexto

El ataque requiere acceso al backend de almacenamiento de sesiones (Redis/Memcached sin autenticación, misconfigured). Con pickle, el atacante solo necesita escribir un payload serializado que ejecute código al deserializarse. Django cambió el serializer por defecto a JSON desde la versión 4.0.

## Referencia

- https://nvd.nist.gov/vuln/detail/CVE-2020-13254
- https://docs.djangoproject.com/en/4.2/topics/http/sessions/#session-serialization
