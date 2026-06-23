from authlib.integrations.starlette_client import OAuth

from ..config import get_settings

_settings = get_settings()
oauth = OAuth()

if _settings.google_client_id and _settings.google_client_secret:
    oauth.register(
        name="google",
        client_id=_settings.google_client_id,
        client_secret=_settings.google_client_secret,
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile"},
    )
