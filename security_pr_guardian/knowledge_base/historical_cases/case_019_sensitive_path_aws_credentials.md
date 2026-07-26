# Case: Lectura de ~/.aws/credentials vía SSRF (Capital One breach 2019)

## CVE

N/A (técnica usada en breach de Capital One)

## CWE asociado

CWE-552

## Descripción

En el breach de Capital One (2019), la atacante explotó un SSRF en un WAF mal configurado para acceder al metadata service de AWS EC2 (`http://169.254.169.254/`) y obtener credenciales IAM temporales. Patrón similar: código que lee `~/.aws/credentials` directamente expone la ruta como target.

## Código vulnerable

```python
import configparser
import os

# Lectura directa del archivo de credenciales AWS
def get_aws_creds():
    config = configparser.ConfigParser()
    creds_path = os.path.expanduser("~/.aws/credentials")
    config.read(creds_path)  # expone la ruta en el código
    return {
        'access_key': config['default']['aws_access_key_id'],
        'secret_key': config['default']['aws_secret_access_key']
    }

# O referencia al metadata service sin IMDSv2
import requests
def get_instance_creds():
    r = requests.get("http://169.254.169.254/latest/meta-data/iam/security-credentials/")
    role = r.text
    creds = requests.get(f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role}")
    return creds.json()
```

## Código corregido

```python
import boto3

# boto3 resuelve credenciales automáticamente via chain:
# env vars → ~/.aws/credentials → IAM role → instance metadata
# No necesitas referencia explícita a archivos
client = boto3.client('s3')  # usa credential chain automática

# Para EC2/ECS: forzar IMDSv2 (requiere token, mitiga SSRF)
# En launch template o user data:
# aws ec2 modify-instance-metadata-options \
#     --instance-id i-xxx \
#     --http-tokens required \
#     --http-endpoint enabled
```

## Contexto

El breach de Capital One expuso 100M+ registros. La combinación de SSRF + metadata service sin IMDSv2 + IAM role con permisos excesivos fue la cadena completa. AWS introdujo IMDSv2 (token-based) como mitigación, pero el código no debería referenciar rutas de credenciales directamente.

## Referencia

- https://blog.appsecco.com/an-ssrf-privileged-aws-keys-and-the-capital-one-breach-4c3c2cded3af
- https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
