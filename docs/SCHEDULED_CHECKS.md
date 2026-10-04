# Scheduled watchlist checks

`openpulse check` is built for unattended runs: bounded input, no
network except live collectors, and `--strict` (exit 1 when anything
is affected) as the CI-gate primitive. `--digest` prints the grouped
summary instead of per-dependency lines — the shape to archive or post.

## Cron (weekly Monday 06:00 UTC)

```cron
0 6 * * 1 cd /opt/OpenPulse && openpulse check --watchlist watchlists/prod.yaml --event events/current.json --digest >> var/checks/$(date +\%F).md
```

Use `--raw-bundle-dir` with checked-in offline bundles when the
schedule must not depend on upstream APIs that day.

Recording is on by default: every scheduled run persists durable
first detections to `.openpulse/detections/` (the detection ledger),
so a warning window survives across cron runs — a re-detected
lifecycle or security fact reports its original first-seen date,
never "today". Pass `--ledger ''` to disable recording for a run
(no claims are made, nothing is written). Point two schedules at
different roots with `--ledger <path>` to keep their histories
independent.

## GitHub Actions (weekly + CI gate)

```yaml
name: watchlist
on:
  schedule: [{cron: "0 6 * * 1"}]
  workflow_dispatch:
permissions:
  contents: read
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
      - uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 # v5
        with: {python-version: "3.11"}
      - run: pip install -U pip "setuptools>=83" && pip install -e .
      - run: openpulse check --watchlist watchlists/prod.yaml --event events/current.json --strict
```

`--strict` fails the workflow exactly when a dependency is affected;
`RELATED`/`UNKNOWN` never fail a gate. Keep the watchlist and the
event files committed next to this recipe so every run is reproducible.

## Posting digests (Slack)

```bash
openpulse check --watchlist watchlists/prod.yaml --event events/current.json \
  --digest --webhook "$SLACK_WEBHOOK_URL" --strict
```

Posts the grouped digest to any JSON-text webhook (Slack incoming
webhook contract: `{"text": "..."}`). Delivery failures warn but never
mask the check result — `--strict` still reflects affected state only.
Store the URL as an Actions secret, never in the repo.

## Watchlist format

See `data/fixtures/watchlist_sample.yaml`. Optional per-dependency
`source`, `environment`, `owner` fields pass through untouched for
future SaaS ingestion.
