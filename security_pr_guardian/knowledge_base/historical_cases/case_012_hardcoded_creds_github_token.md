# Case: GitHub Token hardcodeado en código público (patrón recurrente)

## CVE

N/A (patrón de misconfiguration recurrente)

## CWE asociado

CWE-798

## Descripción

Desarrolladores frecuentemente committean tokens de GitHub (Personal Access Tokens con formato `ghp_*`) directamente en archivos de configuración o scripts. GitHub Secret Scanning detecta millones de secretos expuestos anualmente en repositorios públicos.

## Código vulnerable

```python
# config.py committeado en repositorio público
GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# O en scripts de automatización
headers = {
    "Authorization": "token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh"
}
response = requests.get("https://api.github.com/user", headers=headers)
```

```yaml
# .github/workflows/deploy.yml
env:
  API_KEY: "sk-proj-abc123def456ghi789..."  # OpenAI key expuesta
```

## Código corregido

```python
import os

# Variables de entorno
GITHUB_TOKEN = os.environ["GITHUB_TOKEN"]

# Para CI/CD - usar secrets del runner
# .github/workflows/deploy.yml:
# env:
#   API_KEY: ${{ secrets.OPENAI_API_KEY }}
```

```gitignore
# .gitignore - prevención
.env
.env.local
*.pem
*_key
```

## Contexto

GitHub revoca automáticamente tokens `ghp_*` detectados en repos públicos desde 2022. Pero tokens de terceros (AWS, Stripe, OpenAI) no tienen esta protección. El daño depende de los permisos del token: desde lectura de repos privados hasta push a producción.

## Referencia

- https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning
- https://blog.gitguardian.com/state-of-secrets-sprawl-2023/
