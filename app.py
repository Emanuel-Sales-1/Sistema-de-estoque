import os
import sqlite3
from functools import wraps

from flask import (Flask, abort, flash, g, redirect, render_template,
                   request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

import db
from db import PERFIS, conectar
from validacao import validar_produto

app = Flask(__name__)

chave = os.environ.get("SECRET_KEY")
if not chave:
    raise RuntimeError(
        'Defina a variável de ambiente SECRET_KEY. Exemplo para gerar uma: '
        'python -c "import secrets; print(secrets.token_hex(32))"'
    )

app.config.update(
    SECRET_KEY=chave,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

db.criar_tabelas()

HASH_FALSO = generate_password_hash("qualquer-coisa-aqui")


def quem():
    usuario = g.get("usuario")
    return usuario["usuario"] if usuario else None


@app.before_request
def carregar_usuario():
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
    db.registrar("acesso_negado", f"{request.method} {request.path}", quem())
    return render_template("acesso_negado.html"), 403


@app.errorhandler(404)
def nao_encontrado(erro):
    return render_template(
        "erro.html",
        titulo="Página não encontrada",
        mensagem="O endereço que você tentou abrir não existe.",
    ), 404


@app.errorhandler(405)
def metodo_nao_permitido(erro):
    return render_template(
        "erro.html",
        titulo="Ação não permitida",
        mensagem="Essa ação não pode ser feita por esse caminho.",
    ), 405


@app.errorhandler(400)
def requisicao_invalida(erro):
    return render_template(
        "erro.html",
        titulo="Requisição inválida",
        mensagem="Os dados enviados não puderam ser entendidos.",
    ), 400


@app.errorhandler(500)
def erro_interno(erro):
    return render_template(
        "erro.html",
        titulo="Algo deu errado",
        mensagem="Não foi possível concluir a operação. Tente novamente.",
    ), 500


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.usuario is not None:
        return redirect(url_for("index"))

    if request.method == "POST":
        nome = request.form.get("usuario", "").strip().lower()
        senha = request.form.get("senha", "")

        tamanho_ok = len(nome) <= 50 and len(senha) <= 128
        u = None
        confere = False
        if tamanho_ok:
            with conectar() as con:
                u = con.execute("SELECT * FROM usuarios WHERE usuario=?", (nome,)).fetchone()
            confere = check_password_hash(u["senha_hash"] if u else HASH_FALSO, senha)

        if u is not None and u["ativo"] and confere:
            session.clear()
            session["usuario_id"] = u["id"]
            db.registrar("login", "", u["usuario"])
            return redirect(url_for("index"))

        if u is not None and not u["ativo"]:
            motivo = "conta desativada"
        else:
            motivo = "usuário ou senha incorretos"
        db.registrar("login_falhou", motivo, nome)
        flash("Usuário ou senha inválidos.", "erro")
        return render_template("login.html"), 401

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    if g.usuario is not None:
        db.registrar("logout", "", quem())
    session.clear()
    return redirect(url_for("login"))


def nome_repetido(con, nome, ignorar_id=0):
    return con.execute(
        "SELECT 1 FROM produtos WHERE lower(nome)=lower(?) AND id != ?",
        (nome, ignorar_id),
    ).fetchone() is not None


@app.route("/")
@login_required
def index():
    with conectar() as con:
        produtos = con.execute("SELECT * FROM produtos ORDER BY nome").fetchall()
    return render_template("index.html", produtos=produtos)


@app.route("/adicionar", methods=["POST"])
@login_required
def adicionar():
    dados, erro = validar_produto(request.form)
    if erro:
        flash(erro, "erro")
        return redirect(url_for("index"))

    with conectar() as con:
        if nome_repetido(con, dados["nome"]):
            flash("Já existe um produto com esse nome.", "erro")
            return redirect(url_for("index"))
        con.execute(
            "INSERT INTO produtos (nome, preco, quantidade) VALUES (?, ?, ?)",
            (dados["nome"], dados["preco"], dados["quantidade"]),
        )

    db.registrar(
        "produto_criado",
        f"{dados['nome']} | preço {dados['preco']:.2f} | qtd {dados['quantidade']}",
        quem(),
    )
    flash("Produto cadastrado.", "ok")
    return redirect(url_for("index"))


@app.route("/editar/<int:id>", methods=["POST"])
@login_required
def editar(id):
    with conectar() as con:
        antigo = con.execute("SELECT * FROM produtos WHERE id=?", (id,)).fetchone()
        if antigo is None:
            flash("Produto não encontrado.", "erro")
            return redirect(url_for("index"))

        dados, erro = validar_produto(request.form)
        if erro is None and nome_repetido(con, dados["nome"], id):
            erro = "Já existe outro produto com esse nome."
        if erro:
            flash(erro, "erro")
            return redirect(url_for("index"))

        con.execute(
            "UPDATE produtos SET nome=?, preco=?, quantidade=? WHERE id=?",
            (dados["nome"], dados["preco"], dados["quantidade"], id),
        )

    db.registrar(
        "produto_editado",
        f"id {id}: {antigo['nome']} -> {dados['nome']} | "
        f"preço {antigo['preco']:.2f} -> {dados['preco']:.2f} | "
        f"qtd {antigo['quantidade']} -> {dados['quantidade']}",
        quem(),
    )
    flash("Produto atualizado.", "ok")
    return redirect(url_for("index"))


@app.route("/deletar/<int:id>", methods=["POST"])
@admin_required
def deletar(id):
    with conectar() as con:
        produto = con.execute("SELECT * FROM produtos WHERE id=?", (id,)).fetchone()
        if produto is None:
            flash("Produto não encontrado.", "erro")
            return redirect(url_for("index"))
        con.execute("DELETE FROM produtos WHERE id=?", (id,))

    db.registrar("produto_excluido", f"id {id}: {produto['nome']}", quem())
    flash("Produto excluído.", "ok")
    return redirect(url_for("index"))


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

    db.registrar("usuario_criado", f"{nome} ({perfil})", quem())
    flash(f"Usuário '{nome}' criado.", "ok")
    return redirect(url_for("listar_usuarios"))


@app.route("/usuarios/<int:id>/perfil", methods=["POST"])
@admin_required
def alterar_perfil(id):
    perfil = request.form.get("perfil", "")
    with conectar() as con:
        alvo = con.execute("SELECT usuario, perfil FROM usuarios WHERE id=?", (id,)).fetchone()

    if alvo is None:
        flash("Usuário não encontrado.", "erro")
    elif perfil not in PERFIS:
        flash("Perfil inválido.", "erro")
    elif id == g.usuario["id"]:
        flash("Você não pode alterar o seu próprio perfil.", "erro")
    elif alvo["perfil"] == perfil:
        flash("O usuário já tem esse perfil.", "erro")
    else:
        with conectar() as con:
            con.execute("UPDATE usuarios SET perfil=? WHERE id=?", (perfil, id))
        db.registrar("perfil_alterado", f"{alvo['usuario']}: {alvo['perfil']} -> {perfil}", quem())
        flash("Perfil atualizado.", "ok")
    return redirect(url_for("listar_usuarios"))


@app.route("/usuarios/<int:id>/ativo", methods=["POST"])
@admin_required
def alternar_ativo(id):
    with conectar() as con:
        alvo = con.execute("SELECT usuario, ativo FROM usuarios WHERE id=?", (id,)).fetchone()

    if alvo is None:
        flash("Usuário não encontrado.", "erro")
    elif id == g.usuario["id"]:
        flash("Você não pode desativar a sua própria conta.", "erro")
    else:
        novo = 1 - alvo["ativo"]
        with conectar() as con:
            con.execute("UPDATE usuarios SET ativo=? WHERE id=?", (novo, id))
        acao = "usuario_reativado" if novo else "usuario_desativado"
        db.registrar(acao, alvo["usuario"], quem())
        flash("Conta reativada." if novo else "Conta desativada.", "ok")
    return redirect(url_for("listar_usuarios"))


@app.route("/logs")
@admin_required
def ver_logs():
    filtro_usuario = request.args.get("usuario", "").strip().lower()[:50]
    filtro_acao = request.args.get("acao", "").strip()[:50]

    consulta = "SELECT * FROM logs WHERE 1=1"
    parametros = []
    if filtro_usuario:
        consulta += " AND usuario = ?"
        parametros.append(filtro_usuario)
    if filtro_acao:
        consulta += " AND acao = ?"
        parametros.append(filtro_acao)
    consulta += " ORDER BY id DESC LIMIT 200"

    with conectar() as con:
        logs = con.execute(consulta, parametros).fetchall()
        acoes = [r["acao"] for r in con.execute("SELECT DISTINCT acao FROM logs ORDER BY acao")]

    return render_template(
        "logs.html", logs=logs, acoes=acoes,
        filtro_usuario=filtro_usuario, filtro_acao=filtro_acao,
    )


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
