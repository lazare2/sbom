"""Safe: AWS access key loaded from the environment, never hardcoded."""

import os

AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID")
