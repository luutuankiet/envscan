# Handoff: Brambleway Foods reporting refresh

The weekly refresh for Brambleway broke after the schema change.

- Repo: bwf-dbt-models (private), cloned at <HOME>/alice/dev/bwf-dbt-models
- The models in that repo follow dbt-labs/jaffle-shop layout.
- Landing bucket: s3://bwf-landing-prod
- Dashboard host: grafana.brambleway.lan, login via SSO.
- Their analyst is Priya Ramaswamy (priya.r<AT>brambleway-foods.com).

## Steps already done
1. Re-ran `dbt build --select tag:weekly` locally.
2. Compared row counts: 4,112 vs 4,109, three late rows.
3. Checked the upstream API at https://api.stripe.com/v1/charges; nothing changed there.
4. Opened `reports/bwf-weekly-2026-10-27.xlsx` and confirmed the totals.

## What is left
- Ping @dmorlask to rotate the warehouse key.
- Move the cron from nas01.home.lan to the shared runner.
- Delete the scratch table `scratch.tmp_orders_v2`.
- Confirm with the client whether Q4 includes returns.

## Notes
The tooling is all public: sqlfluff, pre-commit, uv, and ruff 0.6.9.
Nothing in this file should mention credentials.
Timezone stays UTC; week starts Monday.
