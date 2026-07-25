# Case: SQL Injection en Django GIS (CVE-2020-9402)

## CVE

CVE-2020-9402

## CWE asociado

CWE-89

## Descripción

Django antes de 2.2.10 y 3.0.x antes de 3.0.3 permitía SQL injection vía el argumento `tolerance` en funciones GIS (GDALRaster, agregaciones geográficas) cuando se pasaba input del usuario sin sanitizar.

## Código vulnerable

```python
from django.contrib.gis.db.models.functions import Area
queryset = MyModel.objects.annotate(
    area=Area('geom', tolerance=request.GET['tolerance'])
)
```

## Código corregido

```python
from django.contrib.gis.db.models.functions import Area
tolerance = float(request.GET.get('tolerance', 0.05))  # validar tipo
queryset = MyModel.objects.annotate(
    area=Area('geom', tolerance=tolerance)
)
```

## Contexto

El parámetro tolerance se interpolaba directamente en la query SQL generada por Django GIS sin pasar por la parametrización. Cualquier vista que expusiera este parámetro era vulnerable.

## Referencia

- https://nvd.nist.gov/vuln/detail/CVE-2020-9402
- https://www.djangoproject.com/weblog/2020/mar/04/security-releases/
