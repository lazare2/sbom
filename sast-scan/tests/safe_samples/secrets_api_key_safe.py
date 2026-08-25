"""Safe: API key/token loaded from the environment, never hardcoded."""

import os

api_key = os.environ.get("API_KEY")
auth_token = os.environ.get("AUTH_TOKEN")
