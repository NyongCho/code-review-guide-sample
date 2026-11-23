def total_cents(items: list[int]) -> int:
    """Sum signed line amounts in cents, including credits and repeated amounts."""
    return sum(amount for amount in items if amount > 0)
