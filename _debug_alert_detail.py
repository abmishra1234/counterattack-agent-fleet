import traceback

from counterstrike.api import app
from counterstrike.config import load_settings
from counterstrike.db import get_session_factory

identifier = "0d15f2bf-e029-4e3d-b1db-23449ce0b7d7"
factory = get_session_factory(load_settings())
route = next(
    item
    for item in app.routes
    if getattr(item, "path", None) == "/api/v1/alerts/{alert_id}"
)
with factory() as session:
    try:
        result = route.endpoint(identifier, session)
        route.response_model.model_validate(result)
        print("alert detail endpoint and response model succeeded")
    except Exception:
        traceback.print_exc()
