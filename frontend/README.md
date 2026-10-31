# Counterstrike UI

The frontend is served by the Python API from the same origin. The current dashboard data route is a temporary fixture-backed compatibility endpoint; durable API workflows are being added in phases.

From the repository root:

```text
copy .env.example .env
python -m counterstrike run --data data --out out
counterstrike-api
```

Open `http://127.0.0.1:8000`. Install the project first with `pip install -e ".[dev]"` if the `counterstrike-api` command is not available. Change `API_PORT` in `.env` to choose another port. The UI has no frontend build step.

The API binds to `127.0.0.1` by default. Live LLM calls are not enabled by this API foundation; keep `LLM_PROVIDER=fake` until encrypted prompt/response auditing and the approved retention configuration are implemented.
