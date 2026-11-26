import re


RUT_PATTERN = re.compile(r'^(\d{1,3}(?:\.?\d{3}){1,2}|\d{7,8})-?([\dkK])$')


def compute_rut_dv(body_digits: str) -> str:
    """Calcula el dígito verificador chileno según algoritmo oficial Módulo 11."""
    reversed_digits = map(int, reversed(body_digits))
    factors = (2, 3, 4, 5, 6, 7)
    total = 0
    for idx, digit in enumerate(reversed_digits):
        total += digit * factors[idx % 6]
    remainder = 11 - (total % 11)
    if remainder == 11:
        return '0'
    if remainder == 10:
        return 'K'
    return str(remainder)


def is_valid_chilean_rut(value: str) -> bool:
    """Valida formato y dígito verificador Módulo 11 de un RUT chileno."""
    if not isinstance(value, str):
        return False
    cleaned = value.strip()
    match = RUT_PATTERN.match(cleaned)
    if not match:
        return False
    body = match.group(1).replace('.', '')
    dv = match.group(2).upper()
    if not body.isdigit():
        return False
    numeric_body = int(body)
    if numeric_body < 1_000_000 or numeric_body > 99_999_999:
        return False
    return compute_rut_dv(body) == dv


def normalize_chilean_rut(value: str) -> str:
    """Valida con Módulo 11 y normaliza el RUT al formato estándar XX.XXX.XXX-Y."""
    if not is_valid_chilean_rut(value):
        raise ValueError('El RUT ingresado no es válido según el algoritmo Módulo 11.')
    cleaned = value.strip().replace('.', '').replace('-', '')
    body, dv = cleaned[:-1], cleaned[-1].upper()
    formatted_body = f'{int(body):,}'.replace(',', '.')
    return f'{formatted_body}-{dv}'
