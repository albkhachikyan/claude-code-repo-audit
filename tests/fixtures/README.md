# Test fixtures

Everything under `tests/fixtures/` is **inert test data** for `scripts/scan.sh`.

- `evil-repo/` imitates the files a malicious take-home repo carries, so each scanner category has something to hit. Nothing in it works as an attack: all hosts end in `example.invalid` (never resolves), shell lines are `echo FIXTURE`, risky code sits behind `if (false)`, and no payload is real.
- `clean-repo/` is a small normal Express app. `scan.sh` must report no HIGH or CRITICAL for it.
- `git-config` and `git-history` findings need a `.git` directory. A nested `.git` cannot be committed, so `tests/run.sh` builds one in a temporary copy of `evil-repo/` at test time.

Do not run, install or open these directories in an IDE with workspace trust. Scan them with `scripts/scan.sh` or `tests/run.sh` only.
