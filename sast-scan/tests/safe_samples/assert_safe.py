"""Safe: assert used only for non-security data validation, and a real check
used for the security-relevant decision instead of assert."""


def process_items(items: list[int]) -> int:
    assert len(items) > 0, "items must not be empty"
    return sum(items)


def view_admin_panel(user) -> None:
    if not user.is_admin:
        raise PermissionError("must be admin")
    print("welcome, admin")
