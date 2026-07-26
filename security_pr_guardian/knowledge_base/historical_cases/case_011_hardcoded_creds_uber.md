# Case: Hardcoded Credentials en Uber (leak de 2016)

## CVE

N/A (breach disclosure)

## CWE asociado

CWE-798

## Descripción

En 2016, atacantes accedieron a un repositorio privado de Uber en GitHub y encontraron credenciales AWS hardcodeadas en el código. Usaron esas credenciales para acceder a un bucket S3 que contenía datos de 57 millones de usuarios y conductores.

## Código vulnerable

```python
# Patrón encontrado en el repositorio
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

s3_client = boto3.client(
    's3',
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY
)
```

## Código corregido

```python
import boto3

# Opción 1: Variables de entorno (mínimo aceptable)
s3_client = boto3.client('s3')  # boto3 lee AWS_ACCESS_KEY_ID del entorno automáticamente

# Opción 2: IAM Role (recomendado en producción AWS)
# El EC2 instance o Lambda tiene un role asociado — sin credenciales en código

# Opción 3: AWS Secrets Manager para credenciales de terceros
client = boto3.client('secretsmanager')
secret = client.get_secret_value(SecretId='prod/third-party-api-key')
```

## Contexto

El breach afectó 57M usuarios. Uber pagó $100,000 a los atacantes para eliminar los datos (encubrimiento que luego fue multado). Las credenciales tenían permisos excesivos (acceso a S3 con datos de producción). Combina CWE-798 (hardcoded) + violación de least privilege.

## Referencia

- https://www.uber.com/newsroom/2016-data-incident/
- https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password
