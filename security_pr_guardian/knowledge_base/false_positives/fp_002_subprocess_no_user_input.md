# False Positive: subprocess con shell=True sin input del usuario

## Patrón que dispara el detector

```python
subprocess.call("some command", shell=True)
subprocess.run("fixed command | pipe", shell=True)
os.system("static command")
```

## CWE reportado

CWE-78 (OS Command Injection)

## Por qué NO es vulnerable en estos contextos

Command injection requiere que **input controlado por el atacante** llegue al comando. Si el comando es un string literal fijo (constante) sin ninguna variable externa, no hay vector de inyección.

## Criterio para descartar como falso positivo

Si el argumento de subprocess/os.system:
- Es un **string literal** sin interpolación de variables
- Usa solo **constantes definidas en el mismo módulo** (no env vars de input)
- No contiene f-strings, .format(), o % con variables del request/input
- Es un comando de infraestructura que solo corre en setup/build (no en runtime con user input)

→ **Disposición**: no explotable, severidad INFO

## Criterio para CONFIRMAR como verdadero positivo

Si el argumento incluye:
- Variables provenientes de request, argv, env vars controlables por usuario
- f-strings o concatenación con parámetros de función
- Input leído de archivos o bases de datos sin sanitizar
- Cualquier dato que pueda ser influenciado por un atacante

→ **Disposición**: explotable, severidad HIGH/CRITICAL

## Ejemplo de código seguro (falso positivo)

```python
import subprocess

# Comando fijo sin input externo — no es inyectable
subprocess.run("docker compose up -d", shell=True)

# Pipeline con constantes — el shell se usa para el pipe, no para input
subprocess.run("ps aux | grep python | wc -l", shell=True, capture_output=True)

# Script de build/deploy con comandos estáticos
os.system("npm run build && npm run test")
```

## Ejemplo de código vulnerable (verdadero positivo)

```python
# Input del usuario en el comando — SÍ es inyectable
host = request.args.get("host")
subprocess.run(f"ping -c 1 {host}", shell=True)  # VULNERABLE
```
