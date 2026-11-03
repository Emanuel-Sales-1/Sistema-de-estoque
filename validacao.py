import re
from decimal import Decimal, InvalidOperation

PRECO_MAX = Decimal("1000000")
QUANTIDADE_RE = re.compile(r"[0-9]{1,7}")


def validar_produto(form):
    nome = " ".join(form.get("nome", "").split())
    if not 2 <= len(nome) <= 100:
        return None, "O nome deve ter de 2 a 100 caracteres."
    if not nome.isprintable():
        return None, "O nome contém caracteres inválidos."

    texto_preco = form.get("preco", "").strip().replace(",", ".")
    try:
        preco = Decimal(texto_preco)
    except InvalidOperation:
        return None, "Informe um preço válido, por exemplo 12.50."
    if not preco.is_finite() or preco < 0 or preco > PRECO_MAX:
        return None, "O preço deve estar entre 0 e 1.000.000."
    if preco.as_tuple().exponent < -2:
        return None, "O preço deve ter no máximo 2 casas decimais."

    texto_quantidade = form.get("quantidade", "").strip()
    if not QUANTIDADE_RE.fullmatch(texto_quantidade):
        return None, "A quantidade deve ser um número inteiro entre 0 e 9.999.999."

    dados = {
        "nome": nome,
        "preco": float(preco),
        "quantidade": int(texto_quantidade),
    }
    return dados, None
