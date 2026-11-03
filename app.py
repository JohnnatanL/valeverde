"""Reserva do deck — Residencial Vale Verde (Streamlit + PostgreSQL/Neon)."""

import calendar
import hashlib
import hmac
import re
import secrets
import uuid
from datetime import date, datetime, timedelta
from zoneinfo import ZoneInfo

import pandas as pd
import streamlit as st
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError

st.set_page_config(page_title="Deck · Residencial Vale Verde", page_icon="🌿", layout="centered")

# ----------------------------------------------------------------------------
# Configuração
# ----------------------------------------------------------------------------
TZ = ZoneInfo("America/Fortaleza")
APARTAMENTOS = [str(n) for n in [*range(101, 108), *range(201, 208)]]
# chave: (nome, horário, hora em que termina)
TURNOS = {
    "manha": ("Manhã", "7h às 12h", 12),
    "tarde": ("Tarde", "12h às 18h", 18),
    "noite": ("Noite", "18h às 22h", 22),
}
DIAS = ["seg", "ter", "qua", "qui", "sex", "sáb", "dom"]
MESES = ["Janeiro", "Fevereiro", "Março", "Abril", "Maio", "Junho", "Julho",
         "Agosto", "Setembro", "Outubro", "Novembro", "Dezembro"]

SCHEMA = """
CREATE SCHEMA IF NOT EXISTS vale_verde;
CREATE TABLE IF NOT EXISTS vale_verde.moradores (
    id          SERIAL PRIMARY KEY,
    nome        TEXT NOT NULL,
    apartamento TEXT NOT NULL,
    telefone    TEXT,
    pin_hash    TEXT NOT NULL,
    ativo       BOOLEAN NOT NULL DEFAULT TRUE,
    criado_em   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS vale_verde.reservas (
    id          SERIAL PRIMARY KEY,
    data        DATE NOT NULL,
    turno       TEXT NOT NULL CHECK (turno IN ('manha', 'tarde', 'noite')),
    morador_id  INTEGER NOT NULL REFERENCES vale_verde.moradores(id),
    apartamento TEXT NOT NULL,
    grupo       UUID NOT NULL,
    criado_em   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (data, turno)
);
CREATE TABLE IF NOT EXISTS vale_verde.bloqueios (
    data      DATE PRIMARY KEY,
    motivo    TEXT NOT NULL,
    criado_em TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS vale_verde.sindicas (
    id         SERIAL PRIMARY KEY,
    nome       TEXT NOT NULL,
    usuario    TEXT NOT NULL UNIQUE,
    senha_hash TEXT NOT NULL,
    ativo      BOOLEAN NOT NULL DEFAULT TRUE,
    criado_em  TIMESTAMPTZ NOT NULL DEFAULT now()
);
"""


# ----------------------------------------------------------------------------
# Utilitários
# ----------------------------------------------------------------------------
def agora() -> datetime:
    return datetime.now(TZ)


def hoje() -> date:
    return agora().date()


def como_data(x) -> date:
    return x.date() if isinstance(x, datetime) else x


def fmt_data(d) -> str:
    d = como_data(d)
    return f"{DIAS[d.weekday()]}, {d:%d/%m/%Y}"


def fmt_turnos(turnos) -> str:
    sel = set(turnos)
    ordem = [t for t in TURNOS if t in sel]
    if len(ordem) == 3:
        return "Dia todo (7h às 22h)"
    return " + ".join(f"{TURNOS[t][0]} ({TURNOS[t][1]})" for t in ordem)


def hash_pin(pin: str) -> str:
    return hashlib.sha256(f"valeverde:{pin}".encode()).hexdigest()


def gerar_pin() -> str:
    return f"{secrets.randbelow(10000):04d}"


def pin_valido(pin: str) -> bool:
    return pin.isdigit() and len(pin) == 4


def hash_senha(senha: str) -> str:
    """PBKDF2-SHA256 com sal aleatório. Formato: pbkdf2$iteracoes$sal$hash."""
    sal = secrets.token_hex(16)
    it = 300_000
    h = hashlib.pbkdf2_hmac("sha256", senha.encode(), bytes.fromhex(sal), it).hex()
    return f"pbkdf2${it}${sal}${h}"


def confere_senha(senha: str, guardado: str) -> bool:
    try:
        _, it, sal, h = guardado.split("$")
        calc = hashlib.pbkdf2_hmac("sha256", senha.encode(), bytes.fromhex(sal), int(it)).hex()
        return hmac.compare_digest(calc, h)
    except ValueError:
        return False


def turno_passou(d: date, turno: str) -> bool:
    return d == hoje() and agora().hour >= TURNOS[turno][2]


def aviso(msg: str):
    st.session_state["aviso"] = msg


# ----------------------------------------------------------------------------
# Banco de dados
# ----------------------------------------------------------------------------
def url_banco() -> str:
    """Lê o DATABASE_URL e normaliza para postgresql+psycopg2://

    Aceita a URL pura ou colada do painel do Neon com sobras, como
    psql 'postgresql://...' ou com espaços/aspas em volta.
    """
    bruto = str(st.secrets.get("DATABASE_URL", ""))
    achou = re.search(r"postgres(?:ql)?(?:\+\w+)?://[^\s'\"]+", bruto)
    if not achou:
        st.error("DATABASE_URL não encontrado ou inválido nos secrets. "
                 "Ele precisa começar com postgresql:// (copie a connection string do Neon).")
        st.stop()
    # Força o driver psycopg2 (o SQLAlchemy 2.1 passou a usar o psycopg 3 como padrão)
    return re.sub(r"^postgres(?:ql)?(?:\+\w+)?://", "postgresql+psycopg2://", achou.group(0))


@st.cache_resource
def engine():
    eng = create_engine(url_banco(), pool_pre_ping=True, pool_recycle=300)
    with eng.begin() as c:
        c.execute(text(SCHEMA))
    return eng


def consulta(sql: str, **params) -> pd.DataFrame:
    with engine().connect() as c:
        return pd.read_sql(text(sql), c, params=params)


def executa(sql: str, **params):
    with engine().begin() as c:
        return c.execute(text(sql), params)


def moradores_ativos(ap: str) -> pd.DataFrame:
    return consulta(
        "SELECT id, nome FROM vale_verde.moradores WHERE apartamento = :a AND ativo ORDER BY nome", a=ap
    )


def pin_ok(morador_id: int, pin: str) -> bool:
    return not consulta(
        "SELECT 1 FROM vale_verde.moradores WHERE id = :i AND ativo AND pin_hash = :h",
        i=int(morador_id), h=hash_pin(pin or ""),
    ).empty


def situacao_dia(d: date):
    b = consulta("SELECT motivo FROM vale_verde.bloqueios WHERE data = :d", d=d)
    r = consulta("SELECT turno, apartamento FROM vale_verde.reservas WHERE data = :d", d=d)
    motivo = b["motivo"].iloc[0] if not b.empty else None
    return motivo, dict(zip(r["turno"], r["apartamento"]))


def reservar(d: date, turnos: list[str], morador_id: int, ap: str):
    grupo = str(uuid.uuid4())
    try:
        with engine().begin() as c:
            if c.execute(text("SELECT 1 FROM vale_verde.bloqueios WHERE data = :d"), {"d": d}).first():
                return False, "Esse dia foi fechado pela síndica."
            for t in turnos:
                c.execute(
                    text("""INSERT INTO vale_verde.reservas (data, turno, morador_id, apartamento, grupo)
                            VALUES (:d, :t, :m, :a, :g)"""),
                    {"d": d, "t": t, "m": int(morador_id), "a": ap, "g": grupo},
                )
        return True, ""
    except IntegrityError:
        return False, "Alguém acabou de reservar um desses turnos. Confira de novo e tente outra vez."


def reservas_futuras(ap: str | None = None) -> pd.DataFrame:
    filtro = "AND r.apartamento = :a" if ap else ""
    return consulta(
        f"""SELECT r.grupo::text AS grupo, r.data, r.turno, r.apartamento, m.nome, m.telefone
            FROM vale_verde.reservas r JOIN vale_verde.moradores m ON m.id = r.morador_id
            WHERE r.data >= :h {filtro}
            ORDER BY r.data, r.apartamento""",
        h=hoje(), a=ap,
    )


# ----------------------------------------------------------------------------
# Componentes
# ----------------------------------------------------------------------------
def escolher_morador(prefixo: str):
    """Seleção de apartamento + morador + PIN. Retorna (ap, id, nome, pin)."""
    ap = st.selectbox("Apartamento", APARTAMENTOS, index=None,
                      placeholder="Escolha o apartamento", key=f"{prefixo}_ap")
    if not ap:
        return None, None, None, None
    mor = moradores_ativos(ap)
    if mor.empty:
        st.info("Nenhum morador cadastrado neste apartamento. Fale com a síndica.")
        return ap, None, None, None
    nomes = {int(i): n for i, n in zip(mor["id"], mor["nome"])}
    mid = st.selectbox("Morador", list(nomes), format_func=nomes.get, key=f"{prefixo}_mor")
    pin = st.text_input("PIN (4 dígitos)", type="password", max_chars=4, key=f"{prefixo}_pin")
    return ap, mid, nomes.get(mid), pin


def listar_reservas(df: pd.DataFrame, prefixo: str, ap: str | None = None, mostrar_tel=False):
    if df.empty:
        st.info("Nenhuma reserva futura.")
        return
    for grupo, g in df.groupby("grupo", sort=False):
        lin = g.iloc[0]
        contato = f" · {lin['telefone']}" if mostrar_tel and lin["telefone"] else ""
        with st.container(border=True):
            st.markdown(
                f"**{fmt_data(lin['data'])}**  \n{fmt_turnos(g['turno'])}  \n"
                f"Ap {lin['apartamento']} · {lin['nome']}{contato}"
            )
            with st.popover("Cancelar reserva"):
                st.write("Tem certeza que quer cancelar?")
                if st.button("Sim, cancelar", key=f"{prefixo}_cancel_{grupo}", type="primary"):
                    if ap:
                        executa("DELETE FROM vale_verde.reservas WHERE grupo = :g AND apartamento = :a", g=grupo, a=ap)
                    else:
                        executa("DELETE FROM vale_verde.reservas WHERE grupo = :g", g=grupo)
                    aviso("Reserva cancelada.")
                    st.rerun()


# ----------------------------------------------------------------------------
# Telas
# ----------------------------------------------------------------------------
def tela_agenda():
    h = hoje()
    opcoes, a, m = [], h.year, h.month
    for _ in range(6):
        opcoes.append((a, m))
        a, m = (a + 1, 1) if m == 12 else (a, m + 1)
    ano, mes = st.selectbox("Mês", opcoes, format_func=lambda am: f"{MESES[am[1] - 1]} de {am[0]}",
                            key="ag_mes")

    ini = max(date(ano, mes, 1), h)
    fim = date(ano, mes, calendar.monthrange(ano, mes)[1])
    res = consulta("SELECT data, turno, apartamento FROM vale_verde.reservas WHERE data BETWEEN :a AND :b", a=ini, b=fim)
    blq = consulta("SELECT data, motivo FROM vale_verde.bloqueios WHERE data BETWEEN :a AND :b", a=ini, b=fim)
    mapa_res = {(como_data(r.data), r.turno): r.apartamento for r in res.itertuples()}
    mapa_blq = {como_data(r.data): r.motivo for r in blq.itertuples()}

    linhas, d = [], ini
    while d <= fim:
        lin = {"Dia": f"{DIAS[d.weekday()]} {d:%d/%m}"}
        for t, (nome, _, _) in TURNOS.items():
            if d in mapa_blq:
                lin[nome] = f"🔒 {mapa_blq[d]}"
            elif (d, t) in mapa_res:
                lin[nome] = f"🔴 Ap {mapa_res[(d, t)]}"
            elif turno_passou(d, t):
                lin[nome] = "—"
            else:
                lin[nome] = "🟢 Livre"
        linhas.append(lin)
        d += timedelta(days=1)

    st.caption("🟢 livre · 🔴 reservado · 🔒 fechado pela síndica")
    st.dataframe(pd.DataFrame(linhas), hide_index=True, width="stretch",
                 height=min(len(linhas) * 35 + 38, 1150))


def tela_reservar():
    d = st.date_input("Qual dia?", value=hoje(), min_value=hoje(), format="DD/MM/YYYY", key="res_dia")
    motivo, ocupados = situacao_dia(d)

    if motivo:
        st.error(f"🔒 O deck está fechado neste dia: **{motivo}**")
        return

    disponiveis = [t for t in TURNOS if t not in ocupados and not turno_passou(d, t)]
    if not disponiveis:
        st.warning("Não há turnos livres neste dia.")
        return

    st.markdown("**Turnos**")
    dia_todo = False
    if len(disponiveis) == 3:
        dia_todo = st.checkbox("☀️ Dia todo (7h às 22h)", key=f"dt_{d}")

    escolhidos = []
    for t, (nome, horario, _) in TURNOS.items():
        rotulo = f"{nome} ({horario})"
        if t in ocupados:
            st.checkbox(f"{rotulo} — reservado pelo Ap {ocupados[t]}", disabled=True, key=f"oc_{t}_{d}")
        elif turno_passou(d, t):
            st.checkbox(f"{rotulo} — já passou", disabled=True, key=f"ps_{t}_{d}")
        elif st.checkbox(rotulo, value=dia_todo, disabled=dia_todo, key=f"t_{t}_{d}_{dia_todo}") or dia_todo:
            escolhidos.append(t)

    st.divider()
    ap, mid, _, pin = escolher_morador("res")

    if st.button("Confirmar reserva", type="primary", width="stretch",
                 disabled=not (escolhidos and mid)):
        if not pin_ok(mid, pin):
            st.error("PIN incorreto.")
            return
        ok, msg = reservar(d, escolhidos, mid, ap)
        if ok:
            st.session_state.pop("res_pin", None)
            aviso(f"Reservado! {fmt_data(d)} · {fmt_turnos(escolhidos)} · Ap {ap}")
            st.rerun()
        else:
            st.error(msg)


def tela_minhas():
    usuario = st.session_state.get("usuario")
    if not usuario:
        st.caption("Entre com seu apartamento e PIN para ver e cancelar as reservas do seu ap.")
        ap, mid, nome, pin = escolher_morador("min")
        if st.button("Entrar", disabled=not mid, key="min_entrar", width="stretch"):
            if pin_ok(mid, pin):
                st.session_state["usuario"] = {"id": mid, "ap": ap, "nome": nome}
                st.session_state.pop("min_pin", None)
                st.rerun()
            else:
                st.error("PIN incorreto.")
        return

    c1, c2 = st.columns([3, 1], vertical_alignment="center")
    c1.markdown(f"Olá, **{usuario['nome']}** · Ap {usuario['ap']}")
    if c2.button("Sair", key="min_sair"):
        st.session_state.pop("usuario")
        st.rerun()
    listar_reservas(reservas_futuras(usuario["ap"]), "min", ap=usuario["ap"])

    with st.expander("🔑 Trocar meu PIN"):
        with st.form("trocar_pin", clear_on_submit=True):
            atual = st.text_input("PIN atual", type="password", max_chars=4)
            novo = st.text_input("Novo PIN (4 números)", type="password", max_chars=4)
            conf = st.text_input("Repita o novo PIN", type="password", max_chars=4)
            if st.form_submit_button("Salvar novo PIN", type="primary"):
                if not pin_ok(usuario["id"], atual):
                    st.error("PIN atual incorreto.")
                elif not pin_valido(novo):
                    st.error("O novo PIN precisa ter 4 números.")
                elif novo != conf:
                    st.error("Os dois PINs novos não são iguais.")
                else:
                    executa("UPDATE vale_verde.moradores SET pin_hash = :p WHERE id = :i",
                            p=hash_pin(novo), i=int(usuario["id"]))
                    st.success("PIN alterado! Use o novo a partir de agora.")


def mostrar_pin_gerado():
    """Mostra o PIN recém-gerado uma única vez (ele não fica salvo em texto)."""
    info = st.session_state.get("pin_gerado")
    if not info:
        return
    with st.container(border=True):
        st.markdown(f"**PIN de {info['nome']} (Ap {info['ap']}):**")
        st.code(info["pin"], language=None)
        st.caption("Anote e envie para o morador agora. Por segurança, ele não aparece de novo. "
                   "O morador pode trocar depois em \"Minhas reservas\".")
        if st.button("Já anotei", key="pin_ok_btn"):
            st.session_state.pop("pin_gerado")
            st.rerun()


def admin_moradores():
    mostrar_pin_gerado()

    with st.form("novo_morador", clear_on_submit=True):
        st.markdown("**Cadastrar morador**")
        nome = st.text_input("Nome")
        ap = st.selectbox("Apartamento", APARTAMENTOS)
        tel = st.text_input("Telefone (opcional)")
        st.caption("O PIN de 4 números é gerado automaticamente.")
        if st.form_submit_button("Cadastrar", type="primary"):
            if not nome.strip():
                st.error("Informe o nome.")
            else:
                pin = gerar_pin()
                executa("""INSERT INTO vale_verde.moradores (nome, apartamento, telefone, pin_hash)
                           VALUES (:n, :a, :t, :p)""",
                        n=nome.strip(), a=ap, t=tel.strip() or None, p=hash_pin(pin))
                st.session_state["pin_gerado"] = {"nome": nome.strip(), "ap": ap, "pin": pin}
                st.rerun()

    st.markdown("**Moradores**")
    df = consulta("SELECT id, nome, apartamento, telefone, ativo FROM vale_verde.moradores ORDER BY apartamento, nome")
    c1, c2 = st.columns(2, vertical_alignment="bottom")
    filtro = c1.selectbox("Apartamento", ["Todos", *APARTAMENTOS], key="adm_filtro")
    inativos = c2.toggle("Mostrar inativos", key="adm_inativos")
    v = df
    if filtro != "Todos":
        v = v[v["apartamento"] == filtro]
    if not inativos:
        v = v[v["ativo"]]

    if v.empty:
        st.info("Nenhum morador encontrado.")
        return

    tabela = v.assign(Status=v["ativo"].map({True: "Ativo", False: "Inativo"}))
    tabela = tabela[["apartamento", "nome", "telefone", "Status"]].rename(
        columns={"apartamento": "Ap", "nome": "Nome", "telefone": "Telefone"})
    st.dataframe(tabela, hide_index=True, width="stretch")

    opcoes = {int(r.id): f"Ap {r.apartamento} · {r.nome}{'' if r.ativo else ' (inativo)'}"
              for r in v.itertuples()}
    sel = st.selectbox("Gerenciar morador", list(opcoes), format_func=opcoes.get, index=None,
                       placeholder="Escolha um morador", key="adm_sel")
    if sel is None:
        return
    m = df[df["id"] == sel].iloc[0]

    if m["ativo"]:
        if st.button("Desativar morador", key="adm_desat"):
            with engine().begin() as c:
                c.execute(text("UPDATE vale_verde.moradores SET ativo = FALSE WHERE id = :i"), {"i": sel})
                n = c.execute(text("DELETE FROM vale_verde.reservas WHERE morador_id = :i AND data >= :h"),
                              {"i": sel, "h": hoje()}).rowcount
            aviso(f"{m['nome']} desativado. {n} turno(s) reservado(s) no futuro foram liberados.")
            st.rerun()
        st.caption("Ao desativar, as reservas futuras feitas por ele são canceladas.")
    elif st.button("Reativar morador", key="adm_reat"):
        executa("UPDATE vale_verde.moradores SET ativo = TRUE WHERE id = :i", i=sel)
        aviso(f"{m['nome']} reativado.")
        st.rerun()

    if st.button("Gerar novo PIN", key="adm_trocar_pin",
                 help="Use quando o morador esquecer o PIN."):
        pin = gerar_pin()
        executa("UPDATE vale_verde.moradores SET pin_hash = :p WHERE id = :i", p=hash_pin(pin), i=sel)
        st.session_state["pin_gerado"] = {"nome": m["nome"], "ap": m["apartamento"], "pin": pin}
        st.rerun()


def admin_bloqueios():
    st.markdown("**Fechar o deck**")
    periodo = st.date_input("Dia ou período", value=(hoje(),), min_value=hoje(),
                            format="DD/MM/YYYY", key="blq_periodo")
    if not periodo:
        return
    ini, fim = periodo[0], periodo[-1]
    motivo = st.text_input("Motivo", placeholder="Ex.: Natal, Ano Novo, Festa do condomínio", key="blq_motivo")

    afetadas = consulta(
        """SELECT r.grupo::text AS grupo, r.data, r.turno, r.apartamento, m.nome, m.telefone
           FROM vale_verde.reservas r JOIN vale_verde.moradores m ON m.id = r.morador_id
           WHERE r.data BETWEEN :a AND :b ORDER BY r.data""", a=ini, b=fim)
    confirmar = True
    if not afetadas.empty:
        st.warning("Já existem reservas nesse período. Avise os moradores:")
        for _, g in afetadas.groupby("grupo", sort=False):
            lin = g.iloc[0]
            tel = f" · {lin['telefone']}" if lin["telefone"] else ""
            st.markdown(f"- {fmt_data(lin['data'])} · {fmt_turnos(g['turno'])} · "
                        f"Ap {lin['apartamento']} · {lin['nome']}{tel}")
        confirmar = st.checkbox("Cancelar essas reservas e fechar mesmo assim", key="blq_conf")

    if st.button("Fechar deck", type="primary", disabled=not confirmar, key="blq_fechar", width="stretch"):
        if not motivo.strip():
            st.error("Informe o motivo.")
            return
        with engine().begin() as c:
            c.execute(text("DELETE FROM vale_verde.reservas WHERE data BETWEEN :a AND :b"), {"a": ini, "b": fim})
            d = ini
            while d <= fim:
                c.execute(text("""INSERT INTO vale_verde.bloqueios (data, motivo) VALUES (:d, :m)
                                  ON CONFLICT (data) DO UPDATE SET motivo = EXCLUDED.motivo"""),
                          {"d": d, "m": motivo.strip()})
                d += timedelta(days=1)
        aviso("Deck fechado no período escolhido.")
        st.rerun()

    st.divider()
    st.markdown("**Dias fechados**")
    blq = consulta("SELECT data, motivo FROM vale_verde.bloqueios WHERE data >= :h ORDER BY data", h=hoje())
    if blq.empty:
        st.info("Nenhum dia fechado.")
    for r in blq.itertuples():
        c1, c2 = st.columns([3, 1], vertical_alignment="center")
        c1.markdown(f"🔒 **{fmt_data(r.data)}** — {r.motivo}")
        if c2.button("Reabrir", key=f"reab_{como_data(r.data)}"):
            executa("DELETE FROM vale_verde.bloqueios WHERE data = :d", d=como_data(r.data))
            aviso(f"{fmt_data(r.data)} reaberto.")
            st.rerun()


def validar_nova_sindica(nome: str, usuario: str, senha: str, conf: str) -> str | None:
    if not nome.strip():
        return "Informe o nome."
    if not usuario.strip() or " " in usuario.strip():
        return "Informe um usuário sem espaços."
    if len(senha) < 6:
        return "A senha precisa ter pelo menos 6 caracteres."
    if senha != conf:
        return "As senhas não são iguais."
    return None


def criar_sindica(nome: str, usuario: str, senha: str) -> str | None:
    try:
        executa("""INSERT INTO vale_verde.sindicas (nome, usuario, senha_hash)
                   VALUES (:n, :u, :s)""",
                n=nome.strip(), u=usuario.strip().lower(), s=hash_senha(senha))
        return None
    except IntegrityError:
        return "Já existe uma síndica com esse usuário."


def form_primeira_sindica():
    st.info("Primeiro acesso: nenhuma síndica cadastrada ainda. Crie o primeiro login abaixo. "
            "Depois disso, só uma síndica logada pode cadastrar outras.")
    with st.form("primeira_sindica"):
        nome = st.text_input("Nome")
        usuario = st.text_input("Usuário (para entrar)")
        senha = st.text_input("Senha", type="password")
        conf = st.text_input("Repita a senha", type="password")
        if st.form_submit_button("Criar síndica", type="primary"):
            if erro := validar_nova_sindica(nome, usuario, senha, conf):
                st.error(erro)
                return
            # Confere de novo dentro da mesma checagem para não criar se alguém já criou
            if not consulta("SELECT 1 FROM vale_verde.sindicas").empty:
                st.error("Já existe síndica cadastrada. Entre com o login.")
                return
            if erro := criar_sindica(nome, usuario, senha):
                st.error(erro)
                return
            aviso("Síndica criada! Agora é só entrar.")
            st.rerun()


def login_sindica():
    if consulta("SELECT 1 FROM vale_verde.sindicas").empty:
        form_primeira_sindica()
        return
    with st.form("login_sindica"):
        usuario = st.text_input("Usuário")
        senha = st.text_input("Senha", type="password")
        if st.form_submit_button("Entrar", type="primary", width="stretch"):
            r = consulta("""SELECT id, nome, senha_hash FROM vale_verde.sindicas
                            WHERE usuario = :u AND ativo""", u=usuario.strip().lower())
            if not r.empty and confere_senha(senha, r["senha_hash"].iloc[0]):
                st.session_state["admin"] = {"id": int(r["id"].iloc[0]), "nome": r["nome"].iloc[0]}
                st.rerun()
            st.error("Usuário ou senha incorretos.")


def admin_sindicas():
    eu = st.session_state["admin"]

    with st.expander("🔑 Trocar minha senha"):
        with st.form("trocar_senha", clear_on_submit=True):
            atual = st.text_input("Senha atual", type="password")
            nova = st.text_input("Nova senha", type="password")
            conf = st.text_input("Repita a nova senha", type="password")
            if st.form_submit_button("Salvar nova senha", type="primary"):
                r = consulta("SELECT senha_hash FROM vale_verde.sindicas WHERE id = :i", i=eu["id"])
                if r.empty or not confere_senha(atual, r["senha_hash"].iloc[0]):
                    st.error("Senha atual incorreta.")
                elif len(nova) < 6:
                    st.error("A nova senha precisa ter pelo menos 6 caracteres.")
                elif nova != conf:
                    st.error("As senhas novas não são iguais.")
                else:
                    executa("UPDATE vale_verde.sindicas SET senha_hash = :s WHERE id = :i",
                            s=hash_senha(nova), i=eu["id"])
                    st.success("Senha alterada!")

    with st.form("nova_sindica", clear_on_submit=True):
        st.markdown("**Cadastrar síndica**")
        nome = st.text_input("Nome")
        usuario = st.text_input("Usuário (para entrar)")
        senha = st.text_input("Senha inicial", type="password",
                              help="Passe para ela. Depois ela troca em \"Trocar minha senha\".")
        conf = st.text_input("Repita a senha", type="password")
        if st.form_submit_button("Cadastrar", type="primary"):
            if erro := validar_nova_sindica(nome, usuario, senha, conf) or criar_sindica(nome, usuario, senha):
                st.error(erro)
            else:
                st.success(f"{nome.strip()} cadastrada. Usuário: {usuario.strip().lower()}")

    st.markdown("**Síndicas**")
    if temp := st.session_state.get("senha_temp"):
        with st.container(border=True):
            st.markdown(f"**Senha temporária de {temp['nome']}:**")
            st.code(temp["senha"], language=None)
            st.caption("Envie para ela agora. Não aparece de novo. Ela troca depois em \"Trocar minha senha\".")
            if st.button("Já anotei", key="senha_temp_ok"):
                st.session_state.pop("senha_temp")
                st.rerun()

    df = consulta("SELECT id, nome, usuario, ativo FROM vale_verde.sindicas ORDER BY ativo DESC, nome")
    for r in df.itertuples():
        c1, c2, c3 = st.columns([3, 1.2, 1.2], vertical_alignment="center")
        status = "" if r.ativo else " · _inativa_"
        voce = " (você)" if r.id == eu["id"] else ""
        c1.markdown(f"**{r.nome}**{voce} · `{r.usuario}`{status}")
        if r.id == eu["id"]:
            continue
        if c2.button("Nova senha", key=f"sd_pw_{r.id}", help="Para quando ela esquecer a senha."):
            nova = secrets.token_urlsafe(6)
            executa("UPDATE vale_verde.sindicas SET senha_hash = :s WHERE id = :i",
                    s=hash_senha(nova), i=int(r.id))
            st.session_state["senha_temp"] = {"nome": r.nome, "senha": nova}
            st.rerun()
        if r.ativo:
            if c3.button("Desativar", key=f"sd_des_{r.id}"):
                executa("UPDATE vale_verde.sindicas SET ativo = FALSE WHERE id = :i", i=int(r.id))
                aviso(f"{r.nome} desativada.")
                st.rerun()
        elif c3.button("Reativar", key=f"sd_rea_{r.id}"):
            executa("UPDATE vale_verde.sindicas SET ativo = TRUE WHERE id = :i", i=int(r.id))
            aviso(f"{r.nome} reativada.")
            st.rerun()
    st.caption("Ninguém consegue desativar o próprio login, então sempre sobra pelo menos uma síndica ativa.")


def tela_sindica():
    adm = st.session_state.get("admin")
    if adm:
        # Se foi desativada enquanto estava logada, sai
        if consulta("SELECT 1 FROM vale_verde.sindicas WHERE id = :i AND ativo", i=adm["id"]).empty:
            st.session_state.pop("admin")
            adm = None
    if not adm:
        login_sindica()
        return

    c1, c2 = st.columns([3, 1], vertical_alignment="center")
    c1.markdown(f"Olá, **{adm['nome']}**")
    if c2.button("Sair", key="adm_sair"):
        st.session_state.pop("admin")
        st.rerun()

    a1, a2, a3, a4 = st.tabs(["👥 Moradores", "🔒 Fechar dias", "📋 Reservas", "🛡️ Síndicas"])
    with a1:
        admin_moradores()
    with a2:
        admin_bloqueios()
    with a3:
        listar_reservas(reservas_futuras(), "adm", mostrar_tel=True)
    with a4:
        admin_sindicas()


# ----------------------------------------------------------------------------
# App
# ----------------------------------------------------------------------------
st.title("🌿 Residencial Vale Verde")
st.caption("Reserva do deck · Manhã 7h–12h · Tarde 12h–18h · Noite 18h–22h")

if msg := st.session_state.pop("aviso", None):
    st.toast(msg, icon="✅")

aba_agenda, aba_reservar, aba_minhas, aba_sindica = st.tabs(
    ["📅 Agenda", "📝 Reservar", "🔑 Minhas reservas", "🛠️ Síndica"])

with aba_agenda:
    tela_agenda()
with aba_reservar:
    tela_reservar()
with aba_minhas:
    tela_minhas()
with aba_sindica:
    tela_sindica()
