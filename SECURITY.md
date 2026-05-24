# Security Policy

## Supported Versions

Security fixes are made against the latest published `0.x` release line.
Consumers should pin to the latest npm version of `@silmaril-security/sdk`.

## Reporting a Vulnerability

Do not report suspected vulnerabilities in public issues. Use GitHub private
vulnerability reporting for this repository:

https://github.com/Silmaril-Security/sdk-typescript/security/advisories/new

Include the affected SDK version, runtime, integration surface, reproduction
steps, expected behavior, and observed behavior. Avoid attaching production
API keys, tenant URLs, customer data, or raw prompts that contain secrets.

## Secrets

Never commit `.env` files, API keys, tenant URLs, private prompts, captured
traffic, or customer data. Keep examples generic and use placeholders such as
`SILMARIL_API_KEY` and `SILMARIL_API_URL`.

