## What this does and why

<!-- The "why" matters more than the "what" — code changes rot into stale
comments, but a clear reason here helps future readers (including you). -->

## Testing

- [ ] `go test ./...` passes
- [ ] `go test -race ./...` passes
- [ ] `go vet ./...` and `gofmt -l .` are clean
- [ ] Tested against a real running target (not just unit tests), if this touches request-handling behavior
- [ ] If a real bug was found while building/testing this, it's documented in `docs/FINDINGS.md`

## Checklist

- [ ] Tests added for new behavior
- [ ] Docs updated (README / docs/*.md / config comments) if this changes user-facing behavior
