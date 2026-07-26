# Case: AWS Secret Keys hardcodeadas en Lambda Function

## CVE

N/A (patrón de misconfiguration en AWS)

## CWE asociado

CWE-798

## Descripción

Patrón común en funciones Lambda: desarrolladores hardcodean access keys para acceder a otros servicios AWS (S3, DynamoDB, SES) en lugar de usar el IAM Role de la función. Las keys quedan expuestas en el código empaquetado y en logs de CloudWatch.

## Código vulnerable

```python
import boto3

# Lambda function con credenciales hardcodeadas
def lambda_handler(event, context):
    client = boto3.client(
        'ses',
        aws_access_key_id='AKIAI44QH8DHBEXAMPLE',
        aws_secret_access_key='je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY',
        region_name='us-east-1'
    )
    client.send_email(...)
```

## Código corregido

```python
import boto3

# Lambda function usando IAM Role (las credenciales se inyectan automáticamente)
def lambda_handler(event, context):
    # boto3 usa el role de la Lambda automáticamente — sin credenciales en código
    client = boto3.client('ses', region_name='us-east-1')
    client.send_email(...)

# Si necesitas credenciales de terceros:
def lambda_handler(event, context):
    ssm = boto3.client('ssm')
    api_key = ssm.get_parameter(
        Name='/myapp/third-party-api-key',
        WithDecryption=True
    )['Parameter']['Value']
```

## Contexto

Las Lambdas con IAM Roles no necesitan access keys — boto3 las obtiene del metadata service automáticamente. Las keys hardcodeadas son más peligrosas en Lambda porque: (1) el código se puede inspeccionar vía la consola AWS, (2) aparecen en deployment packages descargables, (3) no se rotan automáticamente como las credenciales del role.

## Referencia

- https://docs.aws.amazon.com/lambda/latest/dg/lambda-intro-execution-role.html
- https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html
