# Case: OS Command Injection en node-tar (CVE-2021-32804)

## CVE

CVE-2021-32804

## CWE asociado

CWE-78

## Descripción

El paquete `tar` de npm (usado por npm CLI internamente) antes de 6.1.1 era vulnerable a arbitrary file creation y command injection vía nombres de archivo maliciosos en archivos tar que contenían caracteres especiales del shell.

## Código vulnerable

```javascript
// Extracción de tar sin sanitizar nombres de archivo
const tar = require('tar');
tar.extract({
    file: userUploadedTarball,
    cwd: '/tmp/extract'
    // No validaba nombres de archivo con caracteres peligrosos
});
```

## Código corregido

```javascript
const tar = require('tar');
const path = require('path');

tar.extract({
    file: userUploadedTarball,
    cwd: '/tmp/extract',
    filter: (entryPath) => {
        // Validar que no hay path traversal ni caracteres shell
        const resolved = path.resolve('/tmp/extract', entryPath);
        return resolved.startsWith('/tmp/extract/') &&
               !/[;&|`$]/.test(entryPath);
    }
});
```

## Contexto

npm usa `tar` para instalar paquetes. Un paquete malicioso publicado en npm podía incluir entries con nombres que causaban ejecución de comandos en sistemas donde los filenames se procesaban sin sanitizar.

## Referencia

- https://nvd.nist.gov/vuln/detail/CVE-2021-32804
- https://github.com/npm/node-tar/security/advisories/GHSA-3jfq-g458-7qm9
