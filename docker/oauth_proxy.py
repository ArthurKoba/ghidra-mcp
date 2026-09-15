from __future__ import annotations

import os

from fastmcp.server import create_proxy
from fastmcp.server.auth import AuthContext
from fastmcp.server.auth.providers.github import GitHubProvider
from fastmcp.server.middleware import AuthMiddleware

_CHATGPT_OAUTH_REDIRECT = "https://chatgpt.com/connector_platform_oauth_redirect"


def _required_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


def _split_env(name: str, default: str) -> list[str]:
    value = os.getenv(name, default)
    return [item.strip() for item in value.split(",") if item.strip()]


def _allowed_github_users() -> set[str]:
    return {
        item.strip().casefold()
        for item in _required_env("OAUTH_ALLOWED_GITHUB_USERS").split(",")
        if item.strip()
    }


def _github_user_allowed(ctx: AuthContext) -> bool:
    if ctx.token is None:
        return False
    login = str(ctx.token.claims.get("login", "")).casefold()
    return bool(login) and login in _allowed_github_users()


_auth = GitHubProvider(
    client_id=_required_env("OAUTH_GITHUB_CLIENT_ID"),
    client_secret=_required_env("OAUTH_GITHUB_CLIENT_SECRET"),
    base_url=_required_env("OAUTH_BASE_URL"),
    required_scopes=["read:user"],
    jwt_signing_key=_required_env("OAUTH_JWT_SIGNING_KEY"),
    allowed_client_redirect_uris=[_CHATGPT_OAUTH_REDIRECT],
    require_authorization_consent="external",
    enable_cimd=False,
    fallback_refresh_token_expiry_seconds=30 * 24 * 60 * 60,
    fastmcp_access_token_expiry_seconds=30 * 60,
)

proxy = create_proxy(
    os.getenv("GHIDRA_MCP_UPSTREAM", "http://bridge:8081/mcp"),
    name="ghidra-mcp",
    auth=_auth,
    middleware=[AuthMiddleware(auth=_github_user_allowed)],
)

app = proxy.http_app(
    path="/mcp",
    allowed_hosts=_split_env(
        "MCP_ALLOWED_HOSTS",
        "localhost:*,127.0.0.1:*,[::1]:*",
    ),
    allowed_origins=_split_env(
        "MCP_ALLOWED_ORIGINS",
        "http://localhost:*,http://127.0.0.1:*,http://[::1]:*",
    ),
)
