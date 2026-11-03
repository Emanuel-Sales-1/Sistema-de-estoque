import os
import re
import sqlite3

from werkzeug.security import generate_password_hash

# caminho absoluto: o app e o script criar_admin.py sempre usam o mesmo banco
DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "estoque.db")

PERFIS = ("admin", "comum")
_USUARIO_RE = re.compile(r"^[a-z0-9._-]{3,50}$")


def conectar():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con


def criar_tabelas():
    with conectar() as con:
        con.executescript("""
            CREATE TABLE IF NOT EXISTS produtos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nome TEXT NOT NULL,
                preco REAL NOT NULL,
                quantidade INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                usuario TEXT NOT NULL UNIQUE,
                senha_hash TEXT NOT NULL,
                perfil TEXT NOT NULL CHECK (perfil IN ('admin', 'comum')),
                ativo INTEGER NOT NULL DEFAULT 1
            );
        """)


def validar_credenciais(usuario, senha):
    """Devolve uma mensagem de erro, ou None se estiver tudo certo."""
    if not _USUARIO_RE.match(usuario):
        return "Usuário deve ter de 3 a 50 caracteres: letras minúsculas, números, ponto, hífen ou sublinhado."
    if len(senha) < 8:
        return "A senha deve ter pelo menos 8 caracteres."
    if len(senha) > 128:
        return "A senha deve ter no máximo 128 caracteres."
    return None


def existe_admin():
    with conectar() as con:
        return con.execute(
            "SELECT 1 FROM usuarios WHERE perfil='admin' AND ativo=1 LIMIT 1"
        ).fetchone() is not None


def criar_usuario(usuario, senha, perfil):
    """Grava só o hash da senha. Levanta sqlite3.IntegrityError se o usuário já existir."""
    with conectar() as con:
        con.execute(
            "INSERT INTO usuarios (usuario, senha_hash, perfil) VALUES (?, ?, ?)",
            (usuario, generate_password_hash(senha), perfil),
        )
