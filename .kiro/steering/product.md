---
inclusion: always
---

# Product — Security PR Guardian

## Qué es

Agente especializado que se activa en cada Pull Request de un repositorio
de GitHub, analiza el código modificado y las dependencias afectadas, y
publica un comentario con los riesgos de seguridad reales, priorizados
por severidad. No corrige código, solo reporta con contexto suficiente
para decidir rápido.

## Problema que resuelve

Las herramientas de seguridad tradicionales (linters de dependencias, SAST
básico) generan demasiado ruido: marcan hallazgos sin entender si el
código realmente los explota. Este agente usa razonamiento del LLM en
contexto para filtrar lo que sí importa.

## Usuarios

- Desarrolladores que reciben el comentario del PR.
- Equipos de seguridad que quieren visibilidad sin revisar cada PR a mano.
- Cualquier repositorio público que instale la GitHub Action.

## Objetivos del MVP (hackathon)

1. Detectar patrones de vulnerabilidad en el diff (inyección, secretos
   hardcodeados, deserialización insegura).
2. Detectar CVEs conocidos en dependencias nuevas/modificadas.
3. Usar RAG sobre patrones de vulnerabilidad conocidos (CWE/OWASP) para
   enriquecer el razonamiento del agente.
4. Reducir falsos positivos frente a herramientas tradicionales — esta es
   la métrica de éxito principal en la demo.
5. Publicarse como GitHub Action reutilizable por cualquiera. Y como una herramienta que se pueda ejecutar en terminal

## Fuera de alcance (MVP)

- Remediación automática de código.
- Soporte multi-repo con autenticación compleja.
- Modelos locales (se prioriza nube vía Bedrock/Anthropic).