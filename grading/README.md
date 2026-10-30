# Trainer-only grading set

`hidden_data/` has the same shape as `data/` with different products, versions and traps
(alias for Spring, out-of-range Django major, a different injection phrasing, an unclear bulletin).
Do **not** ship this folder to students. Grade a team's repo with:

```bash
python -m counterstrike run  --data /path/to/grading/hidden_data --out out-hidden
python -m counterstrike eval --out out-hidden --gold /path/to/grading/hidden_data/gold/expected_alerts.json
```

(Use the team's own `python -m counterstrike run`; the `eval` command comes from this solution.)
