"""Run the Counterstrike HTTP API and same-origin frontend."""

from __future__ import annotations


def main() -> None:
    import uvicorn

    from counterstrike.api import app
    from counterstrike.config import Settings

    settings = app.state.settings
    if not isinstance(settings, Settings):
        raise RuntimeError("Counterstrike API settings were not initialized")
    uvicorn.run(
        app,
        host=settings.api_host,
        port=settings.api_port,
        log_config=None,
        access_log=False,
    )


if __name__ == "__main__":
    main()
