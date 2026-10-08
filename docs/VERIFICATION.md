# Verification record

Local checks on 2026-10-02, Windows:

- Python 3.12.14, locked dependencies: 48 tests passed; 96.58% source line coverage.
- Tests include separate spawned processes sharing one SQLite quota, concurrent threads, sibling aggregate quotas, failed-admission rollback, restart persistence, ancestor revocation, replay through sibling grants, signature tampering, action binding and strict wire validation.
- Ruff lint and format checks passed; strict mypy passed for all four source modules.
- The issuer/supervisor/worker/gateway demo admitted one synthetic action and rejected replay, exhausted child quota and a revoked ancestor.
- Source distribution and wheel built successfully. The wheel installed in a fresh Python 3.13.5 environment, and the demo ran successfully from that installed package.
- The full 48-test suite also passed against that installed wheel on Python 3.13.5 with 96.58% source line coverage; wheel contents include `py.typed`.

The test suite uses generated keys and synthetic actions. No external agent provider, production tool, customer workload or live payment was exercised. Linux and Python 3.11/3.14 checks are configured in CI; their results were not observed when this local record was written. Full gateway enforcement, key custody, protocol review, backup recovery, disk failure and load behavior remain unverified deployment work.

## Public release 0.2.0 — 2026-10-08

Windows/Python 3.12.14: 58 tests pass, 96.63% source line coverage. Ruff lint/format and strict mypy pass. Wheel and source builds succeed; all 58 tests also pass against the installed wheel in an isolated environment. Synthetic demos pass. New tests exercise backup overwrite refusal, failure cleanup and isolated restore; restore does not execute adapters.

The Git history and tracked file list were reviewed before publication; a credential-pattern scan found no matches. This is not a guarantee that no secret or vulnerability exists. Review current cross-platform runs in [GitHub Actions](https://github.com/itzKLAUS/delegation-gate/actions/workflows/check.yml). Production workload benchmarks and independent security review remain open.
