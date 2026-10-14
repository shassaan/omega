## What and why

<!-- One or two sentences. Link the issue. -->

## Evidence

- [ ] A test that failed before this change and passes after it
- [ ] `bash scripts/check-all.sh` passes
- [ ] Hook-side code stays Python 3.9+, standard library only
- [ ] Guards still fail closed (deny with exit 2 on internal errors)
- [ ] `docs/ARCHITECTURE.md` / `docs/DECISIONS.md` updated if behaviour changed
- [ ] Commits are signed
