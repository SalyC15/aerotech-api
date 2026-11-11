"""
API REST (Flask) - Reservas de vuelos | Arquitectura SOA
Cliente: Flutter  ->  Servicios REST (Flask)  ->  Supabase (PostgreSQL)

Endpoints:
  POST /api/usuarios/registro
  POST /api/auth/login
  GET  /api/vuelos              (cliente y administrador; filtros origen/destino/fecha)
  POST /api/vuelos              (solo administrador: crea vuelo y su capacidad)
  PUT  /api/vuelos/<id>         (solo administrador)
  DELETE /api/vuelos/<id>       (solo administrador)
  GET  /api/usuarios            (solo administrador)
  POST /api/usuarios            (solo administrador: crea usuarios con rol)
  GET  /api/vuelos/<id>/asientos          (mapa del avión)
  POST /api/vuelos/<id>/asientos/retener  (retiene asientos 5 min mientras se decide)
  DELETE /api/vuelos/<id>/asientos/retener
  POST /api/reservas            (asientos concretos: {"vuelo_id":1,"asientos":["3A","3B"]})
  GET  /api/reservas            (lista del usuario)
  GET  /api/reservas/<id>
  PUT  /api/reservas/<id>       (actualizar cantidad de asientos)
  DELETE /api/reservas/<id>     (cancelar)
  GET  /api/reservas/<id>/factura   (XML)
Soporta JSON (por defecto) y XML con ?formato=xml en consultas.
"""
import os
import uuid
from contextlib import contextmanager
import datetime as dt
from decimal import Decimal
from functools import wraps
from xml.etree import ElementTree as ET

import jwt
import psycopg2
import psycopg2.extras
from dotenv import load_dotenv
from flask import Flask, jsonify, request, Response, g
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

app = Flask(__name__)
CORS(app)

DATABASE_URL = os.environ["DATABASE_URL"]
JWT_SECRET = os.environ.get("JWT_SECRET", "dev-secret")
JWT_HORAS = int(os.environ.get("JWT_HORAS", "2"))
IVA = Decimal("0.15")


# ---------------------------------------------------------------- utilidades
def get_conn():
    extra = {"sslmode": os.environ["DB_SSLMODE"]} if os.environ.get("DB_SSLMODE") else {}
    return psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor, **extra)


@contextmanager
def db():
    """Una transacción por petición: confirma al salir bien, deshace si hay error
    y SIEMPRE cierra la conexión (importante con muchas consultas simultáneas)."""
    conn = get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                yield cur
    finally:
        conn.close()


def serializar(valor):
    if isinstance(valor, Decimal):
        return float(valor)
    if isinstance(valor, (dt.datetime, dt.date, dt.time)):
        return valor.isoformat()
    return valor


def fila_a_dict(fila):
    return {k: serializar(v) for k, v in fila.items()} if fila else None


def dict_a_xml(raiz, datos):
    """Convierte un dict (o lista de dicts) a XML simple."""
    def agregar(padre, clave, valor):
        if isinstance(valor, list):
            cont = ET.SubElement(padre, clave)
            for item in valor:
                agregar(cont, "item", item)
        elif isinstance(valor, dict):
            cont = ET.SubElement(padre, clave)
            for k, v in valor.items():
                agregar(cont, k, v)
        else:
            ET.SubElement(padre, clave).text = "" if valor is None else str(valor)

    elem = ET.Element(raiz)
    if isinstance(datos, dict):
        for k, v in datos.items():
            agregar(elem, k, v)
    else:
        for item in datos:
            agregar(elem, "item", item)
    return ET.tostring(elem, encoding="utf-8", xml_declaration=True)


def responder(datos, codigo=200, raiz="respuesta"):
    """Responde en JSON o XML según ?formato=xml o cabecera Accept."""
    quiere_xml = (
        request.args.get("formato") == "xml"
        or "application/xml" in request.headers.get("Accept", "")
    )
    if quiere_xml:
        return Response(dict_a_xml(raiz, datos), status=codigo, mimetype="application/xml")
    return jsonify(datos), codigo


def error(mensaje, codigo=400):
    return responder({"error": mensaje}, codigo, "error")


@app.errorhandler(psycopg2.errors.DeadlockDetected)
@app.errorhandler(psycopg2.errors.SerializationFailure)
def _conflicto_concurrencia(e):
    return error("Otra persona modificó los mismos asientos al mismo tiempo. Intenta de nuevo.", 409)


@app.errorhandler(psycopg2.OperationalError)
def _bd_no_disponible(e):
    app.logger.error("Error de conexión con la base de datos: %s", str(e).strip().splitlines()[0])
    return error("No se pudo conectar con la base de datos", 503)


# ---------------------------------------------------------------------- JWT
def crear_token(usuario_id):
    expira = dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=JWT_HORAS)
    token = jwt.encode(
        {"sub": str(usuario_id), "exp": expira, "jti": uuid.uuid4().hex},
        JWT_SECRET,
        algorithm="HS256",
    )
    with db() as cur:
        cur.execute(
            "insert into tokens (usuario_id, token, expiracion, estado) "
            "values (%s, %s, %s, 'activo')",
            (usuario_id, token, expira),
        )
    return token, expira


def requiere_token(f):
    @wraps(f)
    def envoltura(*args, **kwargs):
        cabecera = request.headers.get("Authorization", "")
        if not cabecera.startswith("Bearer "):
            return error("Falta el token (Authorization: Bearer <token>)", 401)
        token = cabecera[7:]
        try:
            datos = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return error("Token expirado", 401)
        except jwt.InvalidTokenError:
            return error("Token inválido", 401)
        with db() as cur:
            cur.execute(
                "select t.estado, u.rol from tokens t "
                "join usuarios u on u.id = t.usuario_id where t.token = %s",
                (token,),
            )
            fila = cur.fetchone()
        if not fila or fila["estado"] != "activo":
            return error("Token revocado o no registrado", 401)
        g.usuario_id = int(datos["sub"])
        g.rol = fila["rol"]
        return f(*args, **kwargs)
    return envoltura


def requiere_rol(*roles):
    """Debe usarse DESPUÉS de @requiere_token (queda más cerca de la función)."""
    def decorador(f):
        @wraps(f)
        def envoltura(*args, **kwargs):
            if g.rol not in roles:
                return error("No tienes permiso para esta acción", 403)
            return f(*args, **kwargs)
        return envoltura
    return decorador


ROLES = ("cliente", "administrador")


def validar_vuelo(d, parcial=False):
    """Valida y normaliza los datos de un vuelo. Devuelve (datos, mensaje_error)."""
    out = {}
    for campo in ("origen", "destino"):
        if campo in d or not parcial:
            v = str(d.get(campo) or "").strip()
            if not v:
                return None, f"{campo} es obligatorio"
            out[campo] = v
    if "fecha" in d or not parcial:
        try:
            out["fecha"] = dt.date.fromisoformat(str(d.get("fecha")))
        except ValueError:
            return None, "fecha inválida (use AAAA-MM-DD)"
    for campo in ("hora_salida", "hora_llegada"):
        if campo in d or not parcial:
            try:
                out[campo] = dt.time.fromisoformat(str(d.get(campo)))
            except ValueError:
                return None, f"{campo} inválida (use HH:MM)"
    if "precio" in d or not parcial:
        try:
            precio = Decimal(str(d.get("precio")))
        except Exception:
            return None, "precio inválido"
        if precio <= 0:
            return None, "El precio debe ser mayor que 0"
        out["precio"] = precio
    if "capacidad" in d or not parcial:
        c = d.get("capacidad")
        if isinstance(c, bool) or not isinstance(c, int) or c < 1:
            return None, "capacidad debe ser un entero >= 1"
        out["capacidad"] = c
    if "origen" in out and "destino" in out and out["origen"].lower() == out["destino"].lower():
        return None, "El origen y el destino no pueden ser iguales"
    return out, None



# ------------------------------------------------------------ asientos y concurrencia
LETRAS = "ABCDEF"      # 6 asientos por fila: A B C | pasillo | D E F
HOLD_SEGUNDOS = 300    # un asiento elegido queda retenido 5 minutos
MAX_ASIENTOS = 8       # máximo de asientos por reserva


def ordenar(codigos):
    return sorted(codigos, key=lambda c: (int(c[:-1]), c[-1]))


def crear_asientos(cur, vuelo_id, cantidad, existentes=()):
    """Crea `cantidad` asientos nuevos (1A, 1B, ... 1F, 2A, ...) saltando los que ya existen."""
    filas, i = [], 0
    while len(filas) < cantidad:
        fila, letra = i // 6 + 1, LETRAS[i % 6]
        if f"{fila}{letra}" not in existentes:
            filas.append((vuelo_id, fila, letra, f"{fila}{letra}"))
        i += 1
    if filas:
        psycopg2.extras.execute_values(
            cur, "insert into asientos_vuelo (vuelo_id, fila, letra, codigo) values %s", filas)


def normalizar_codigos(lista):
    """Valida la lista de asientos pedida. Devuelve (codigos, mensaje_de_error)."""
    if not isinstance(lista, list) or not all(isinstance(x, str) for x in lista):
        return None, 'asientos debe ser una lista de códigos, por ejemplo ["1A","1B"]'
    codigos = list(dict.fromkeys(x.strip().upper() for x in lista if x.strip()))
    if not all(len(c) >= 2 and c[:-1].isdigit() and c[-1] in LETRAS for c in codigos):
        return None, "Código de asiento inválido (use fila y letra A-F, por ejemplo 12C)"
    if len(codigos) > MAX_ASIENTOS:
        return None, f"Máximo {MAX_ASIENTOS} asientos por reserva"
    return codigos, None


def bloquear_asientos(cur, vuelo_id, codigos, usuario_id, reserva_id=None):
    """Bloquea (FOR UPDATE) los asientos pedidos, los que el usuario tiene retenidos y los de
    la reserva indicada, SIEMPRE en el mismo orden (fila, letra) para evitar interbloqueos.
    Mientras dure la transacción nadie más puede tomarlos."""
    condiciones, params = ["codigo = any(%s::varchar[])", "retenido_por = %s"], [list(codigos), usuario_id]
    if reserva_id is not None:
        condiciones.append("reserva_id = %s")
        params.append(reserva_id)
    cur.execute(
        "select id, codigo, estado, reserva_id, retenido_por, "
        "coalesce(retenido_hasta > now(), false) as retenido_activo "
        "from asientos_vuelo where vuelo_id = %s and (" + " or ".join(condiciones) + ") "
        "order by fila, letra for update",
        [vuelo_id, *params])
    return cur.fetchall()


def conflictos_asientos(filas, codigos, usuario_id, reserva_id=None):
    """Devuelve (inexistentes, no_disponibles) entre los códigos pedidos."""
    por_codigo = {f["codigo"]: f for f in filas}
    inexistentes = [c for c in codigos if c not in por_codigo]
    no_disponibles = []
    for c in codigos:
        f = por_codigo.get(c)
        if not f:
            continue
        if f["estado"] == "reservado" and (reserva_id is None or f["reserva_id"] != reserva_id):
            no_disponibles.append(c)
        elif f["retenido_activo"] and f["retenido_por"] != usuario_id:
            no_disponibles.append(c)
    return inexistentes, no_disponibles


def respuesta_conflicto(inexistentes, no_disponibles):
    if inexistentes:
        return responder({"error": f"El asiento {', '.join(inexistentes)} no existe en este vuelo",
                          "conflictos": inexistentes}, 404)
    uno = len(no_disponibles) == 1
    texto = (f"El asiento {no_disponibles[0]} ya no está disponible" if uno else
             f"Los asientos {', '.join(no_disponibles)} ya no están disponibles")
    return responder({"error": texto, "conflictos": no_disponibles}, 409)


def asientos_auto(cur, vuelo_id, cantidad, usuario_id, excluir=()):
    """Elige `cantidad` asientos libres (sin retención ajena) y los bloquea."""
    cur.execute(
        "select codigo from asientos_vuelo where vuelo_id = %s and estado = 'libre' "
        "and (retenido_hasta is null or retenido_hasta <= now() or retenido_por = %s) "
        "and not (codigo = any(%s::varchar[])) order by fila, letra limit %s for update",
        (vuelo_id, usuario_id, list(excluir), cantidad))
    return [f["codigo"] for f in cur.fetchall()]


def mapa_asientos(cur, vuelo_id, usuario_id):
    """Estado del avión desde el punto de vista de `usuario_id`:
    libre | ocupado (comprado) | retenido (lo eligió otra persona) | mio (lo eligió él)."""
    cur.execute(
        "select codigo, fila, letra, "
        "case when estado = 'reservado' then 'ocupado' "
        "     when coalesce(retenido_hasta > now(), false) and retenido_por = %s then 'mio' "
        "     when coalesce(retenido_hasta > now(), false) then 'retenido' "
        "     else 'libre' end as estado, "
        "case when coalesce(retenido_hasta > now(), false) and retenido_por = %s "
        "     then greatest(0, extract(epoch from (retenido_hasta - now())))::int end as segundos "
        "from asientos_vuelo where vuelo_id = %s order by fila, letra",
        (usuario_id, usuario_id, vuelo_id))
    filas = cur.fetchall()
    segundos = [f["segundos"] for f in filas if f["segundos"] is not None]
    return {
        "vuelo_id": vuelo_id,
        "hold_segundos": HOLD_SEGUNDOS,
        "expira_en": min(segundos) if segundos else None,
        "asientos": [{"codigo": f["codigo"], "fila": f["fila"], "letra": f["letra"],
                      "estado": f["estado"]} for f in filas],
    }


# --------------------------------------------------------------- endpoints
@app.get("/api/salud")
def salud():
    return responder({"estado": "ok"})


@app.post("/api/usuarios/registro")
def registro():
    d = request.get_json(silent=True) or {}
    # El registro público SIEMPRE crea clientes; el rol no se puede elegir aquí.
    nombre, correo, password = d.get("nombre"), d.get("correo"), d.get("password")
    if not (nombre and correo and password):
        return error("nombre, correo y password son obligatorios")
    if len(password) < 6:
        return error("La contraseña debe tener al menos 6 caracteres")
    try:
        with db() as cur:
            cur.execute(
                "insert into usuarios (nombre, correo, password_hash, rol) "
                "values (%s, %s, %s, 'cliente') "
                "returning id, nombre, correo, rol, fecha_registro",
                (nombre, correo.lower().strip(), generate_password_hash(password)),
            )
            usuario = cur.fetchone()
    except psycopg2.errors.UniqueViolation:
        return error("El correo ya está registrado", 409)
    return responder(
        {"mensaje": "Usuario registrado", "usuario": fila_a_dict(usuario)}, 201
    )


@app.post("/api/auth/login")
def login():
    d = request.get_json(silent=True) or {}
    correo, password = d.get("correo"), d.get("password")
    if not (correo and password):
        return error("correo y password son obligatorios")
    with db() as cur:
        cur.execute(
            "select id, nombre, rol, password_hash from usuarios where correo = %s",
            (correo.lower().strip(),),
        )
        u = cur.fetchone()
    if not u or not check_password_hash(u["password_hash"], password):
        return error("Credenciales incorrectas", 401)
    token, expira = crear_token(u["id"])
    return responder(
        {
            "mensaje": "Login correcto",
            "token": token,
            "expiracion": expira.isoformat(),
            "usuario": {"id": u["id"], "nombre": u["nombre"], "correo": correo.lower().strip(), "rol": u["rol"]},
        }
    )


def patron_like(texto):
    """Búsqueda parcial e insensible a mayúsculas; escapa % _ \\ del usuario."""
    t = texto.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{t}%"


@app.get("/api/vuelos")
@requiere_token
def listar_vuelos():
    # El cliente solo ve vuelos con asientos; el administrador ve todos.
    filtros, params = [], []
    if g.rol != "administrador":
        filtros.append("asientos_disponibles > 0")
    for campo in ("origen", "destino"):
        valor = (request.args.get(campo) or "").strip()
        if valor:
            filtros.append(f"{campo} ilike %s escape '\\'")
            params.append(patron_like(valor))
    fecha = (request.args.get("fecha") or "").strip()
    if fecha:
        filtros.append("fecha = %s")
        params.append(fecha)
    donde = f" where {' and '.join(filtros)}" if filtros else ""
    sql = f"select * from vuelos{donde} order by fecha, hora_salida"
    with db() as cur:
        cur.execute(sql, params)
        filas = [fila_a_dict(f) for f in cur.fetchall()]
    datos = {"vuelos": filas}
    if not filas:
        datos["mensaje"] = "Vuelo no encontrado"
    return responder(datos, raiz="vuelos")


@app.post("/api/vuelos")
@requiere_token
@requiere_rol("administrador")
def crear_vuelo():
    datos, msg = validar_vuelo(request.get_json(silent=True) or {})
    if msg:
        return error(msg)
    with db() as cur:
        cur.execute(
            "insert into vuelos (origen, destino, fecha, hora_salida, hora_llegada, "
            "precio, capacidad, asientos_disponibles) "
            "values (%s, %s, %s, %s, %s, %s, %s, %s) returning *",
            (datos["origen"], datos["destino"], datos["fecha"], datos["hora_salida"],
             datos["hora_llegada"], datos["precio"], datos["capacidad"], datos["capacidad"]),
        )
        v = cur.fetchone()
        crear_asientos(cur, v["id"], v["capacidad"])
    return responder({"mensaje": "Vuelo creado", "vuelo": fila_a_dict(v)}, 201)


@app.put("/api/vuelos/<int:vuelo_id>")
@requiere_token
@requiere_rol("administrador")
def actualizar_vuelo(vuelo_id):
    datos, msg = validar_vuelo(request.get_json(silent=True) or {}, parcial=True)
    if msg:
        return error(msg)
    if not datos:
        return error("No se envió ningún campo para actualizar")
    with db() as cur:
        cur.execute("select * from vuelos where id = %s for update", (vuelo_id,))
        actual = cur.fetchone()
        if not actual:
            return error("Vuelo no encontrado", 404)
        origen = datos.get("origen", actual["origen"])
        destino = datos.get("destino", actual["destino"])
        if origen.lower() == destino.lower():
            return error("El origen y el destino no pueden ser iguales")
        # asientos ya vendidos = capacidad anterior - disponibles
        vendidos = actual["capacidad"] - actual["asientos_disponibles"]
        capacidad = datos.get("capacidad", actual["capacidad"])
        if capacidad < vendidos:
            return error(f"La capacidad no puede ser menor a los {vendidos} asientos ya reservados", 409)
        datos["asientos_disponibles"] = capacidad - vendidos
        if capacidad > actual["capacidad"]:
            cur.execute("select codigo from asientos_vuelo where vuelo_id = %s", (vuelo_id,))
            crear_asientos(cur, vuelo_id, capacidad - actual["capacidad"],
                           {f["codigo"] for f in cur.fetchall()})
        elif capacidad < actual["capacidad"]:
            # se quitan los últimos asientos LIBRES (los comprados nunca se tocan)
            cur.execute(
                "delete from asientos_vuelo where id in (select id from asientos_vuelo "
                "where vuelo_id = %s and estado = 'libre' order by fila desc, letra desc limit %s)",
                (vuelo_id, actual["capacidad"] - capacidad))
        columnas = ", ".join(f"{k} = %s" for k in datos)
        cur.execute(f"update vuelos set {columnas} where id = %s returning *",
                    (*datos.values(), vuelo_id))
        v = cur.fetchone()
    return responder({"mensaje": "Vuelo actualizado", "vuelo": fila_a_dict(v)})


@app.delete("/api/vuelos/<int:vuelo_id>")
@requiere_token
@requiere_rol("administrador")
def eliminar_vuelo(vuelo_id):
    with db() as cur:
        cur.execute("select count(*) as n from reservas where vuelo_id = %s", (vuelo_id,))
        if cur.fetchone()["n"] > 0:
            return error("El vuelo tiene reservas y no se puede eliminar", 409)
        cur.execute("delete from vuelos where id = %s returning id", (vuelo_id,))
        if not cur.fetchone():
            return error("Vuelo no encontrado", 404)
    return responder({"mensaje": "Vuelo eliminado", "vuelo_id": vuelo_id})


@app.get("/api/usuarios")
@requiere_token
@requiere_rol("administrador")
def listar_usuarios():
    with db() as cur:
        cur.execute("select id, nombre, correo, rol, fecha_registro from usuarios order by id")
        filas = [fila_a_dict(f) for f in cur.fetchall()]
    return responder({"usuarios": filas}, raiz="usuarios")


@app.post("/api/usuarios")
@requiere_token
@requiere_rol("administrador")
def crear_usuario():
    """Solo el administrador puede crear usuarios con un rol elegido."""
    d = request.get_json(silent=True) or {}
    nombre, correo, password = d.get("nombre"), d.get("correo"), d.get("password")
    rol = d.get("rol", "cliente")
    if not (nombre and correo and password):
        return error("nombre, correo y password son obligatorios")
    if len(password) < 6:
        return error("La contraseña debe tener al menos 6 caracteres")
    if rol not in ROLES:
        return error("rol debe ser 'cliente' o 'administrador'")
    try:
        with db() as cur:
            cur.execute(
                "insert into usuarios (nombre, correo, password_hash, rol) "
                "values (%s, %s, %s, %s) returning id, nombre, correo, rol, fecha_registro",
                (nombre.strip(), correo.lower().strip(), generate_password_hash(password), rol),
            )
            u = cur.fetchone()
    except psycopg2.errors.UniqueViolation:
        return error("El correo ya está registrado", 409)
    return responder({"mensaje": "Usuario creado", "usuario": fila_a_dict(u)}, 201)


# ---------------------------------------------------------- mapa de asientos (avión)
@app.get("/api/vuelos/<int:vuelo_id>/asientos")
@requiere_token
def ver_asientos(vuelo_id):
    with db() as cur:
        cur.execute("select id from vuelos where id = %s", (vuelo_id,))
        if not cur.fetchone():
            return error("Vuelo no encontrado", 404)
        mapa = mapa_asientos(cur, vuelo_id, g.usuario_id)
    return responder(mapa, raiz="mapa")


@app.post("/api/vuelos/<int:vuelo_id>/asientos/retener")
@requiere_token
def retener_asientos(vuelo_id):
    """El usuario indica la lista COMPLETA de asientos que quiere. Se retienen para él durante
    HOLD_SEGUNDOS (los demás los ven 'en proceso') y se sueltan los que ya no pidió.
    Todo ocurre en una transacción: o se obtienen todos, o no cambia nada (409)."""
    d = request.get_json(silent=True) or {}
    codigos, msg = normalizar_codigos(d.get("asientos", []))
    if msg:
        return error(msg)
    with db() as cur:
        cur.execute("select id from vuelos where id = %s", (vuelo_id,))
        if not cur.fetchone():
            return error("Vuelo no encontrado", 404)
        filas = bloquear_asientos(cur, vuelo_id, codigos, g.usuario_id)
        inexistentes, no_disponibles = conflictos_asientos(filas, codigos, g.usuario_id)
        if inexistentes or no_disponibles:
            return respuesta_conflicto(inexistentes, no_disponibles)
        cur.execute(
            "update asientos_vuelo set retenido_por = null, retenido_hasta = null "
            "where vuelo_id = %s and retenido_por = %s and not (codigo = any(%s::varchar[]))",
            (vuelo_id, g.usuario_id, codigos))
        if codigos:
            cur.execute(
                "update asientos_vuelo set retenido_por = %s, "
                "retenido_hasta = now() + make_interval(secs => %s) "
                "where vuelo_id = %s and codigo = any(%s::varchar[])",
                (g.usuario_id, HOLD_SEGUNDOS, vuelo_id, codigos))
        mapa = mapa_asientos(cur, vuelo_id, g.usuario_id)
    return responder(mapa, raiz="mapa")


@app.delete("/api/vuelos/<int:vuelo_id>/asientos/retener")
@requiere_token
def liberar_asientos(vuelo_id):
    """Suelta todas las retenciones del usuario en este vuelo (al salir de la pantalla)."""
    with db() as cur:
        bloquear_asientos(cur, vuelo_id, [], g.usuario_id)
        cur.execute("update asientos_vuelo set retenido_por = null, retenido_hasta = null "
                    "where vuelo_id = %s and retenido_por = %s", (vuelo_id, g.usuario_id))
    return responder({"mensaje": "Asientos liberados"})


# ---------------------------------------------------------------------- reservas
@app.post("/api/reservas")
@requiere_token
def crear_reserva():
    """Reserva asientos concretos: {"vuelo_id": 1, "asientos": ["3A","3B"]}.
    (Compatibilidad: {"vuelo_id": 1, "cantidad": 2} asigna los primeros libres.)"""
    d = request.get_json(silent=True) or {}
    vuelo_id, cantidad = d.get("vuelo_id"), d.get("cantidad")
    if not isinstance(vuelo_id, int) or isinstance(vuelo_id, bool):
        return error("vuelo_id es obligatorio")
    codigos = None
    if d.get("asientos") is not None:
        codigos, msg = normalizar_codigos(d["asientos"])
        if msg:
            return error(msg)
        if not codigos:
            return error("Elige al menos un asiento")
    elif not (isinstance(cantidad, int) and not isinstance(cantidad, bool)
              and 1 <= cantidad <= MAX_ASIENTOS):
        return error('Indica los asientos (asientos: ["1A","1B"]) o la cantidad de pasajeros (1 a 8)')

    with db() as cur:
        # 1) se bloquea el vuelo y 2) sus asientos: dos compras del mismo asiento se ponen en
        #    fila y la segunda ve que ya está ocupado (nunca se vende dos veces).
        cur.execute("select * from vuelos where id = %s for update", (vuelo_id,))
        vuelo = cur.fetchone()
        if not vuelo:
            return error("Vuelo no encontrado", 404)
        if codigos is None:
            bloquear_asientos(cur, vuelo_id, [], g.usuario_id)
            codigos = asientos_auto(cur, vuelo_id, cantidad, g.usuario_id)
            if len(codigos) < cantidad:
                return error("No hay asientos suficientes", 409)
        else:
            filas = bloquear_asientos(cur, vuelo_id, codigos, g.usuario_id)
            inexistentes, no_disponibles = conflictos_asientos(filas, codigos, g.usuario_id)
            if inexistentes or no_disponibles:
                return respuesta_conflicto(inexistentes, no_disponibles)
        codigos = ordenar(codigos)
        total = vuelo["precio"] * len(codigos)
        cur.execute(
            "insert into reservas (usuario_id, vuelo_id, cantidad_asientos, total, estado) "
            "values (%s, %s, %s, %s, 'confirmada') returning id, total, estado",
            (g.usuario_id, vuelo_id, len(codigos), total))
        r = cur.fetchone()
        cur.execute(
            "update asientos_vuelo set estado = 'reservado', reserva_id = %s, "
            "retenido_por = null, retenido_hasta = null "
            "where vuelo_id = %s and codigo = any(%s::varchar[])",
            (r["id"], vuelo_id, codigos))
        cur.execute("update asientos_vuelo set retenido_por = null, retenido_hasta = null "
                    "where vuelo_id = %s and retenido_por = %s", (vuelo_id, g.usuario_id))
        cur.execute("update vuelos set asientos_disponibles = asientos_disponibles - %s "
                    "where id = %s", (len(codigos), vuelo_id))
    return responder(
        {"mensaje": "Reserva creada", "reserva_id": r["id"], "total": float(r["total"]),
         "estado": r["estado"], "asientos": codigos},
        201)


SQL_RESERVA = """
select r.id, r.usuario_id, r.vuelo_id, r.cantidad_asientos, r.total, r.estado,
       r.fecha_reserva, v.origen, v.destino, v.fecha, v.hora_salida, v.hora_llegada,
       v.precio, u.nombre as cliente,
       (select string_agg(a.codigo, ',' order by a.fila, a.letra)
          from asientos_vuelo a where a.reserva_id = r.id) as asientos
from reservas r
join vuelos v on v.id = r.vuelo_id
join usuarios u on u.id = r.usuario_id
"""


@app.get("/api/reservas")
@requiere_token
def listar_reservas():
    with db() as cur:
        cur.execute(SQL_RESERVA + " where r.usuario_id = %s order by r.fecha_reserva desc",
                    (g.usuario_id,))
        filas = [fila_a_dict(f) for f in cur.fetchall()]
    return responder({"reservas": filas}, raiz="reservas")


def obtener_reserva(cur, reserva_id):
    cur.execute(SQL_RESERVA + " where r.id = %s and r.usuario_id = %s",
                (reserva_id, g.usuario_id))
    return cur.fetchone()


@app.get("/api/reservas/<int:reserva_id>")
@requiere_token
def ver_reserva(reserva_id):
    with db() as cur:
        r = obtener_reserva(cur, reserva_id)
    if not r:
        return error("Reserva no encontrada", 404)
    return responder(fila_a_dict(r), raiz="reserva")


@app.put("/api/reservas/<int:reserva_id>")
@requiere_token
def actualizar_reserva(reserva_id):
    """Cambia los asientos ({"asientos": [...]}) o la cantidad ({"cantidad": n}: quita los
    últimos asientos o agrega los primeros libres)."""
    d = request.get_json(silent=True) or {}
    objetivo, nueva = None, d.get("cantidad")
    if d.get("asientos") is not None:
        objetivo, msg = normalizar_codigos(d["asientos"])
        if msg:
            return error(msg)
        if not objetivo:
            return error("Elige al menos un asiento")
    elif not (isinstance(nueva, int) and not isinstance(nueva, bool) and 1 <= nueva <= MAX_ASIENTOS):
        return error("Indica asientos (lista) o cantidad (entero entre 1 y 8)")

    with db() as cur:
        cur.execute("select vuelo_id from reservas where id = %s and usuario_id = %s",
                    (reserva_id, g.usuario_id))
        fila = cur.fetchone()
        if not fila:
            return error("Reserva no encontrada", 404)
        vuelo_id = fila["vuelo_id"]
        cur.execute("select id from vuelos where id = %s for update", (vuelo_id,))
        r = obtener_reserva(cur, reserva_id)          # se lee DESPUÉS de bloquear el vuelo
        if r["estado"] != "confirmada":
            return error("Solo se pueden modificar reservas confirmadas", 409)
        filas = bloquear_asientos(cur, vuelo_id, objetivo or [], g.usuario_id, reserva_id)
        actuales = ordenar([f["codigo"] for f in filas if f["reserva_id"] == reserva_id])
        if objetivo is not None:
            inexistentes, no_disponibles = conflictos_asientos(filas, objetivo, g.usuario_id, reserva_id)
            if inexistentes or no_disponibles:
                return respuesta_conflicto(inexistentes, no_disponibles)
        elif nueva <= len(actuales):
            objetivo = actuales[:nueva]
        else:
            extra = asientos_auto(cur, vuelo_id, nueva - len(actuales), g.usuario_id, excluir=actuales)
            if len(extra) < nueva - len(actuales):
                return error("No hay asientos suficientes", 409)
            objetivo = actuales + extra
        objetivo = ordenar(objetivo)
        agregar = [c for c in objetivo if c not in actuales]
        quitar = [c for c in actuales if c not in objetivo]
        if quitar:
            cur.execute("update asientos_vuelo set estado = 'libre', reserva_id = null "
                        "where reserva_id = %s and codigo = any(%s::varchar[])", (reserva_id, quitar))
        if agregar:
            cur.execute("update asientos_vuelo set estado = 'reservado', reserva_id = %s, "
                        "retenido_por = null, retenido_hasta = null "
                        "where vuelo_id = %s and codigo = any(%s::varchar[])",
                        (reserva_id, vuelo_id, agregar))
        cur.execute("update asientos_vuelo set retenido_por = null, retenido_hasta = null "
                    "where vuelo_id = %s and retenido_por = %s", (vuelo_id, g.usuario_id))
        total = r["precio"] * len(objetivo)
        cur.execute("update reservas set cantidad_asientos = %s, total = %s where id = %s",
                    (len(objetivo), total, reserva_id))
        cur.execute("update vuelos set asientos_disponibles = asientos_disponibles + %s "
                    "where id = %s", (len(quitar) - len(agregar), vuelo_id))
    return responder({"mensaje": "Reserva actualizada", "reserva_id": reserva_id,
                      "total": float(total), "asientos": objetivo})


@app.delete("/api/reservas/<int:reserva_id>")
@requiere_token
def cancelar_reserva(reserva_id):
    with db() as cur:
        cur.execute("select vuelo_id from reservas where id = %s and usuario_id = %s",
                    (reserva_id, g.usuario_id))
        fila = cur.fetchone()
        if not fila:
            return error("Reserva no encontrada", 404)
        vuelo_id = fila["vuelo_id"]
        cur.execute("select id from vuelos where id = %s for update", (vuelo_id,))
        bloquear_asientos(cur, vuelo_id, [], g.usuario_id, reserva_id)
        # UPDATE condicional: si dos cancelaciones llegan a la vez, solo una encuentra
        # la reserva 'confirmada'; la otra recibe 0 filas (no se devuelven asientos dos veces).
        cur.execute("update reservas set estado = 'cancelada' "
                    "where id = %s and estado = 'confirmada' returning cantidad_asientos",
                    (reserva_id,))
        r = cur.fetchone()
        if not r:
            return error("La reserva ya está cancelada", 409)
        cur.execute("update asientos_vuelo set estado = 'libre', reserva_id = null "
                    "where reserva_id = %s", (reserva_id,))
        liberados = cur.rowcount or r["cantidad_asientos"]
        cur.execute("update vuelos set asientos_disponibles = asientos_disponibles + %s "
                    "where id = %s", (liberados, vuelo_id))
    return responder({"mensaje": "Reserva cancelada", "reserva_id": reserva_id})


@app.get("/api/reservas/<int:reserva_id>/factura")
@requiere_token
def factura_xml(reserva_id):
    """Comprobante en XML (interoperabilidad)."""
    with db() as cur:
        r = obtener_reserva(cur, reserva_id)
    if not r:
        return error("Reserva no encontrada", 404)
    subtotal = r["total"]
    iva = (subtotal * IVA).quantize(Decimal("0.01"))
    total = subtotal + iva
    f = ET.Element("factura")
    ET.SubElement(f, "numero").text = f"P001-{r['id']:06d}"
    ET.SubElement(f, "fecha").text = r["fecha_reserva"].date().isoformat()
    ET.SubElement(f, "cliente").text = r["cliente"]
    ET.SubElement(f, "ruta").text = f"{r['origen']} - {r['destino']}"
    ET.SubElement(f, "fecha_vuelo").text = r["fecha"].isoformat()
    ET.SubElement(f, "pasajeros").text = str(r["cantidad_asientos"])
    if r.get("asientos"):
        ET.SubElement(f, "asientos").text = r["asientos"]
    ET.SubElement(f, "subtotal").text = f"{subtotal:.2f}"
    ET.SubElement(f, "iva").text = f"{iva:.2f}"
    ET.SubElement(f, "total").text = f"{total:.2f}"
    return Response(ET.tostring(f, encoding="utf-8", xml_declaration=True),
                    mimetype="application/xml")


if __name__ == "__main__":
    # Solo desarrollo local. En Render se usa gunicorn (ver Procfile).
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")),
            debug=os.environ.get("FLASK_DEBUG", "1") == "1")