---
name: firmar-agent
description: "Workspace-level custom agent for the firmar project: handles code navigation, task-specific instructions, and automated workflows."
---

# Firmar Custom Agent

## Purpose
- Provide a reusable agent persona for this repository.
- Add project-specific context and best practices to reduce onboarding friction.

## Usage
- Trigger by typing `/firmar-agent` if your environment supports custom agents.
- Include task details such as: "fix bug in digital signature flow", "add new API endpoint", "update UI i18n".

## Behavior
- Enriches responses with existing code path conventions under `com.firmar`.
- Uses `java` and Spring Boot idioms; favors tests under `src/test/java`.
- Looks for Maven modules and the embedded `firmadigital-libreria-4.2.0` dependency.

## Notes
- Keep this agent lightweight; major workflows should still be implemented as shared scripts and documented in `README.md`.
