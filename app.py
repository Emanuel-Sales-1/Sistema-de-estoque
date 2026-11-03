import os
import sqlite3
from functools import wraps

from flask import (Flask, abort, flash, g, redirect, render_template,
                   request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

import db
from db import PERFIS, conectar

app = Flask(__name__)

# A chave que assina o cookie de sessão NUNCA fica no código: vem do ambiente.
_chave = os.environ.get("SECRET_KEY")
if not _chave:
    raise RuntimeError(
        "Defina a variável de ambiente SECRET_KEY. Para gerar uma:\n"
        '  python -c "import secrets; print(secrets.token_hex(32))"'
    )

app.config.update(
    SECRET_KEY=_chave,
    SESSION_COOKIE_HTTPONLY=True,                         # JavaScript não lê o cookie
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("PRODUCAO") == "1",  # só HTTPS em produção
)

db.criar_tabelas()


def admin_inicial_por_ambiente():
    """Opcional: cria o 1º admin a partir de variáveis de ambiente (útil no deploy,
    onde não há terminal). Só age se ainda não existir nenhum admin."""
    usuario = os.environ.get("ADMIN_USUARIO", "").strip().lower()
    senha = os.environ.get("ADMIN_SENHA", "")
    if not usuario or not senha or db.existe_admin():
        return
    erro = db.validar_credenciais(usuario, senha)
    if erro:
        raise RuntimeError(f"ADMIN_USUARIO/ADMIN_SENHA inválidos: {erro}")
    try:
        db.criar_usuario(usuario, senha, "admin")
    except sqlite3.IntegrityError:
        pass


admin_inicial_por_ambiente()

# Hash "de mentira": o login gasta o mesmo tempo mesmo quando o usuário não existe.
DUMMY_HASH = generate_password_hash("senha-para-igualar-o-tempo-de-resposta")


# ------------------------------------------------------------ SESSÃO E ACESSO
@app.before_request
def carregar_usuario():
    """A sessão guarda só o id. Perfil e situação vêm do banco a cada requisição,
    então desativar uma conta ou mudar o perfil vale na hora."""
    g.usuario = None
    uid = session.get("usuario_id")
    if uid is None:
        return
    with conectar() as con:
        u = con.execute(
            "SELECT id, usuario, perfil FROM usuarios WHERE id=? AND ativo=1", (uid,)
        ).fetchone()
    if u is None:
        session.clear()
    else:
        g.usuario = u


@app.context_processor
def injetar_usuario():
    return {"usuario": g.get("usuario")}


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if g.usuario is None:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if g.usuario is None:
            return redirect(url_for("login"))
        if g.usuario["perfil"] != "admin":
            abort(403)
        return f(*args, **kwargs)
    return wrapper


@app.errorhandler(403)
def acesso_negado(erro):
    return render_template("acesso_negado.html"), 403


# --------------------------------------------------------------- LOGIN/LOGOUT
@app.route("/login", methods=["GET", "POST"])
def login():
    if g.usuario is not None:
        return redirect(url_for("index"))

    if request.method == "POST":
        nome = request.form.get("usuario", "").strip().lower()
        senha = request.form.get("senha", "")

        with conectar() as con:
            u = con.execute("SELECT * FROM usuarios WHERE usuario=?", (nome,)).fetchone()

        senha_confere = check_password_hash(u["senha_hash"] if u else DUMMY_HASH, senha)

        if u is not None and u["ativo"] and senha_confere:
            session.clear()                 # descarta qualquer sessão anterior
            session["usuario_id"] = u["id"]
            return redirect(url_for("index"))

        # mensagem genérica: não revela se o erro foi no usuário ou na senha
        flash("Usuário ou senha inválidos.", "erro")
        return render_template("login.html"), 401

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


# ------------------------------------------------------------------- PRODUTOS
# READ
@app.route("/")
@login_required
def index():
    with conectar() as con:
        produtos = con.execute("SELECT * FROM produtos ORDER BY nome").fetchall()
    return render_template("index.html", produtos=produtos)


# CREATE
@app.route("/adicionar", methods=["POST"])
@login_required
def adicionar():
    with conectar() as con:
        con.execute(
            "INSERT INTO produtos (nome, preco, quantidade) VALUES (?, ?, ?)",
            (request.form["nome"], request.form["preco"], request.form["quantidade"]),
        )
    return redirect(url_for("index"))


# UPDATE
@app.route("/editar/<int:id>", methods=["POST"])
@login_required
def editar(id):
    with conectar() as con:
        con.execute(
            "UPDATE produtos SET nome=?, preco=?, quantidade=? WHERE id=?",
            (request.form["nome"], request.form["preco"], request.form["quantidade"], id),
        )
    return redirect(url_for("index"))


# DELETE: só admin
@app.route("/deletar/<int:id>", methods=["POST"])
@admin_required
def deletar(id):
    with conectar() as con:
        con.execute("DELETE FROM produtos WHERE id=?", (id,))
    return redirect(url_for("index"))


# ------------------------------------------------------------------- USUÁRIOS
@app.route("/usuarios")
@admin_required
def listar_usuarios():
    with conectar() as con:
        usuarios = con.execute(
            "SELECT id, usuario, perfil, ativo FROM usuarios ORDER BY usuario"
        ).fetchall()
    return render_template("usuarios.html", usuarios=usuarios)


@app.route("/usuarios/adicionar", methods=["POST"])
@admin_required
def adicionar_usuario():
    nome = request.form.get("usuario", "").strip().lower()
    senha = request.form.get("senha", "")
    perfil = request.form.get("perfil", "")

    erro = db.validar_credenciais(nome, senha)
    if perfil not in PERFIS:
        erro = "Perfil inválido."
    if erro:
        flash(erro, "erro")
        return redirect(url_for("listar_usuarios"))

    try:
        db.criar_usuario(nome, senha, perfil)
    except sqlite3.IntegrityError:
        flash("Esse nome de usuário já existe.", "erro")
        return redirect(url_for("listar_usuarios"))

    flash(f"Usuário '{nome}' criado.", "ok")
    return redirect(url_for("listar_usuarios"))


@app.route("/usuarios/<int:id>/perfil", methods=["POST"])
@admin_required
def alterar_perfil(id):
    perfil = request.form.get("perfil", "")
    if perfil not in PERFIS:
        flash("Perfil inválido.", "erro")
    elif id == g.usuario["id"]:
        flash("Você não pode alterar o seu próprio perfil.", "erro")
    else:
        with conectar() as con:
            con.execute("UPDATE usuarios SET perfil=? WHERE id=?", (perfil, id))
    return redirect(url_for("listar_usuarios"))


@app.route("/usuarios/<int:id>/ativo", methods=["POST"])
@admin_required
def alternar_ativo(id):
    if id == g.usuario["id"]:
        flash("Você não pode desativar a sua própria conta.", "erro")
    else:
        with conectar() as con:
            con.execute("UPDATE usuarios SET ativo = 1 - ativo WHERE id=?", (id,))
    return redirect(url_for("listar_usuarios"))


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
