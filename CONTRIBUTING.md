# Contributing to RTCAgent

Thanks for your interest in improving RTCAgent! This document describes how to
build, test and submit changes.

## Prerequisites

- Go **1.25+** (see `go.mod`).
- For building the eBPF objects: `clang`, `llvm` (`llc`, `llvm-strip`) and
  `bpftool`. The `builder/init_env.sh` script installs everything needed on
  Ubuntu.
- Root privileges are required to load the eBPF programs at runtime.

## Building

```bash
make            # full build (eBPF + assets + binary)
make nocore     # build without BTF/CO-RE (older kernels)
```

The resulting binary is written to `bin/rtcagent`. Do not commit build output
(`bin/` is git-ignored).

## Testing

Run the unit tests before opening a pull request:

```bash
go build ./...
go vet ./...
go test -race ./...
gofmt -l .        # must print nothing (generated files are excluded in CI)
```

## Submitting changes

1. Fork the repository and create a topic branch.
2. Keep changes focused; one logical change per pull request.
3. Add or update tests for behaviour changes and bug fixes.
4. Make sure `go build ./...`, `go vet ./...`, `go test -race ./...` and
   `gofmt` are clean (the CI workflow enforces all of them).
5. Use clear commit messages, e.g. `fix(hepclient): verify TLS certificates`.
6. Open a pull request and describe **what** changed and **why**.

## Reporting security issues

Please follow [SECURITY.md](SECURITY.md) instead of opening a public issue.