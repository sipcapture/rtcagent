# Security Policy

## Supported versions

Only the latest release of RTCAgent receives security fixes.

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

Report vulnerabilities privately through either of these channels:

- GitHub's [private vulnerability reporting](https://github.com/sipcapture/rtcagent/security/advisories/new)
  (preferred), or
- email to **support@qxip.net**.

Please include:

- a description of the issue and its impact,
- the affected version/commit,
- steps to reproduce (proof-of-concept if possible),
- any suggested mitigation.

We aim to acknowledge reports within a few business days and will keep you
informed about the fix and disclosure timeline.

## Scope

RTCAgent runs with elevated privileges and reads kernel eBPF data, so
vulnerabilities affecting the agent process, its HEP forwarding (including TLS
verification), its build/release pipeline, or its shipped containers are all in
scope.