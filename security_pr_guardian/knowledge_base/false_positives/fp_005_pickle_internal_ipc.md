# False Positive: pickle usado en IPC interno o caché local

## Patrón que dispara el detector

```python
pickle.loads(data)
pickle.load(file)
pickle.dumps(obj)
```

## CWE reportado

CWE-502 (Deserialization of Untrusted Data)

## Por qué NO es vulnerable en estos contextos

Pickle solo es peligroso cuando los **datos deserializados provienen de una fuente no confiable** (red, usuario, archivo uploaded). Hay usos internos donde el riesgo es nulo o aceptable:

- **Caché local en disco**: datos generados y consumidos por el mismo proceso/servidor
- **IPC entre procesos del mismo sistema**: multiprocessing queues, shared memory
- **Serialización de modelos ML en pipelines internos**: modelo entrenado internamente, no recibido de usuarios
- **Joblib/celery con broker confiable**: workers que procesan tareas internas

## Criterio para descartar como falso positivo

Si los datos deserializados:
- Provienen de un **archivo local generado por el mismo sistema** (caché, checkpoint)
- Viajan por **canales internos confiables** (multiprocessing.Queue, Redis privado sin acceso externo)
- Son **modelos ML entrenados internamente** (no uploaded por usuarios)
- Están **firmados criptográficamente** antes de deserializar (HMAC verification)

→ **Disposición**: no explotable, severidad LOW/INFO

## Criterio para CONFIRMAR como verdadero positivo

Si los datos deserializados:
- Provienen del **request HTTP** (body, cookies, headers)
- Vienen de **archivos uploaded** por usuarios
- Se reciben de un **servicio externo** o API de terceros
- Viajan por **canales accesibles** externamente (Redis público, S3 bucket sin restricción)
- No tienen **verificación de integridad** (sin firma HMAC)

→ **Disposición**: explotable, severidad CRITICAL

## Ejemplo de código seguro (falso positivo)

```python
import pickle
from multiprocessing import Queue

# IPC interno entre procesos del mismo sistema — trusted
queue = Queue()
queue.put(pickle.dumps({"status": "done", "result": 42}))

# Cache local generado por el mismo proceso
CACHE_PATH = "/tmp/app_cache.pkl"
def save_cache(data):
    with open(CACHE_PATH, "wb") as f:
        pickle.dump(data, f)
def load_cache():
    with open(CACHE_PATH, "rb") as f:
        return pickle.load(f)  # datos propios, no de usuario
```

## Ejemplo de código vulnerable (verdadero positivo)

```python
# Datos del request HTTP deserializados — SÍ es RCE
@app.route("/upload-model", methods=["POST"])
def upload_model():
    model = pickle.loads(request.data)  # VULNERABLE — datos del usuario
```
