# CWE-78: Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)

## Descripción

OS Command Injection ocurre cuando una aplicación construye un comando del sistema operativo usando input no confiable sin sanitización adecuada. El atacante puede inyectar comandos adicionales que se ejecutan con los privilegios del proceso.

## Impacto

- Ejecución arbitraria de comandos en el servidor
- Lectura/escritura de archivos del sistema
- Reverse shell y acceso remoto persistente
- Movimiento lateral en la red interna
- Compromiso total del sistema

## Vectores de ataque comunes

- `os.system()` con input del usuario
- `subprocess.call/run/Popen` con `shell=True` e input variable
- Backticks o `$()` en scripts shell generados dinámicamente
- `eval()` combinado con input externo

## Patrones vulnerables típicos

```python
# Python - os.system con input directo
os.system(f"ping {user_input}")

# Python - subprocess con shell=True
subprocess.call(f"grep {pattern} /var/log/app.log", shell=True)

# Python - Popen con shell=True
proc = subprocess.Popen(f"convert {filename} output.png", shell=True)

# Node.js
exec(`ls ${req.query.dir}`, callback)
```

## Remediación

- **Nunca usar `shell=True` con input externo**
- Pasar argumentos como lista a subprocess: `subprocess.run(["ping", "-c", "1", host])`
- Usar `shlex.quote()` si shell=True es absolutamente necesario
- Validar input con whitelist estricta (solo caracteres alfanuméricos)
- Usar APIs de alto nivel en lugar de comandos shell (ej: `shutil` en vez de `cp`)

## Código corregido

```python
# Python - subprocess sin shell, argumentos como lista
subprocess.run(["ping", "-c", "1", validated_host], capture_output=True)

# Python - shlex.quote si shell es inevitable
import shlex
subprocess.run(f"grep {shlex.quote(pattern)} /var/log/app.log", shell=True)

# Mejor: usar API de Python directamente
import ipaddress
addr = ipaddress.ip_address(user_input)  # valida formato
subprocess.run(["ping", "-c", "1", str(addr)])
```

## OWASP relacionado

- A03:2021 — Injection

## Referencias

- https://cwe.mitre.org/data/definitions/78.html
- https://owasp.org/Top10/A03_2021-Injection/
- https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html
