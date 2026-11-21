# Keycloak delegated-admin scope-mapping PoC — evidence package

Evidence package for Sorona report SOR-EC0RS7: a delegated administrator holding only the `manage-clients` role can add the `realm-admin` role to a client's scope mappings, after which a victim's token carries all 22 realm-management roles and Admin API requests return 200.

Tested against the official Keycloak 26.8.2 distribution in `start-dev` mode, fresh realm per run, default settings. Reproduced in three identical runs (16 Nov 2026 x2, fresh run 21 Nov 2026).

Contents:
- `proof2.py` — executable PoC used for the original runs 2 and 3
- `proof3.py` — same steps, extended to record a complete HTTP trace; used for the fresh run
- `run.sh` — harness that starts a fresh Keycloak 26.8.2 and executes the script
- `http-trace.txt` — complete HTTP request/response trace of the fresh run (46 exchanges)
- `poc-terminal-recording.typescript`, `poc-terminal-transcript.txt` — terminal recording of the full fresh run and its plain-text transcript
- `proof-log-2026-11-21.txt` — step-by-step summary log of the fresh run
- `original-run2-proof-log-2026-11-16.txt`, `original-run3-proof-log-2026-11-16.txt` — step logs of the two original runs
- `token-victim-*.json` — decoded victim access-token payloads at each stage
- `realm-rep.json` — realm representation used for setup

All tokens and credentials in this package belong to throwaway local instances and expire with them. Scripts use only the Python 3 standard library.
