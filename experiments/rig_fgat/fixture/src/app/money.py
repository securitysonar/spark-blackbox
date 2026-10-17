from decimal import Decimal, ROUND_HALF_EVEN

def round_cents(amount):
    return Decimal(amount).quantize(Decimal('0.01'), rounding=ROUND_HALF_EVEN)
