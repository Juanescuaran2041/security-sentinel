# False Positive: ORM query con interpolación que NO es SQL injection

## Patrón que dispara el detector

```python
f"SELECT * FROM {table_name}"
f"...WHERE {column} = %s"
query = f"INSERT INTO {MODEL_TABLE} ..."
```

## CWE reportado

CWE-89 (SQL Injection)

## Por qué NO es vulnerable en estos contextos

El detector busca f-strings o format strings que contienen keywords SQL. Pero hay casos donde la interpolación es sobre **metadatos controlados por el desarrollador** (nombres de tablas, columnas), no sobre **valores del usuario**:

- **Table/column names dinámicos pero controlados**: el valor viene de un enum o constante, no del request
- **Query builders internos**: frameworks que construyen SQL con metadatos del modelo
- **Migrations y DDL**: scripts de migración que generan CREATE TABLE con nombres fijos
- **ORM internals**: código del framework que interpola metadatos del esquema

## Criterio para descartar como falso positivo

Si la variable interpolada:
- Es una **constante del módulo** o class attribute (no proviene de input externo)
- Proviene de un **enum o whitelist cerrada** de valores válidos
- Es un **nombre de tabla/columna** definido en el modelo (no user input)
- Los **valores** de la query (WHERE, INSERT VALUES) usan **placeholders** (`%s`, `?`, `:param`)

→ **Disposición**: no explotable, severidad INFO

## Criterio para CONFIRMAR como verdadero positivo

Si la variable interpolada:
- Proviene de `request.args`, `request.form`, `sys.argv`, o cualquier input externo
- Es un **valor** de la query (no un metadato del esquema)
- No hay parametrización para los valores del usuario
- No hay validación de whitelist antes de la interpolación

→ **Disposición**: explotable, severidad CRITICAL

## Ejemplo de código seguro (falso positivo)

```python
# Nombre de tabla como constante — no es inyectable
TABLE_NAME = "users"
cursor.execute(f"SELECT * FROM {TABLE_NAME} WHERE id = %s", (user_id,))

# Query builder interno con metadatos del modelo
class UserRepository:
    TABLE = "users"
    COLUMNS = ["id", "name", "email"]
    
    def find_by_id(self, user_id: int):
        cols = ", ".join(self.COLUMNS)
        # Interpolación de metadatos + parametrización de valores
        cursor.execute(f"SELECT {cols} FROM {self.TABLE} WHERE id = %s", (user_id,))
```

## Ejemplo de código vulnerable (verdadero positivo)

```python
# Input del usuario interpolado en el valor — SÍ es SQL injection
name = request.args.get("name")
cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")  # VULNERABLE
```
