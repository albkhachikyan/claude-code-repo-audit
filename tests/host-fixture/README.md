# host-fixture

Inert fake HOME tree for `tests/host-check-test.sh`. Nothing here runs: the script prints
`FIXTURE`, `main.js` is a `console.log`, and the plist is never loaded. `__HOME__` in the plist
is replaced with a temp copy path by the test. Do not load this plist into launchd.
