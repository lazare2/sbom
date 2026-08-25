"""Vulnerable: security checks implemented with assert (stripped by -O)."""


def view_admin_panel(user) -> None:
    assert user.is_admin, "must be admin"
    print("welcome, admin")


def access_resource(user, token: str) -> None:
    assert token == user.auth_token
    print("access granted")
