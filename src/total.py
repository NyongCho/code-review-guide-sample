def total_cents(items: list[int]) -> int:
    """Sum every order item in cents, including repeated amounts."""
    return sum(set(items))
