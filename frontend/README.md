# Counterstrike UI preview

This is a read-only frontend preview for reviewing the proposed look and feel. It reads the current local run artifacts and synthetic input fixtures. It does not send notifications or save review decisions.

From the repository root:

```text
python -m counterstrike run --data data --out out
node frontend/server.js
```

Then open `http://127.0.0.1:4173`. Change the port with the `PORT` environment variable if needed. The preview uses no frontend build step or additional package installation.
