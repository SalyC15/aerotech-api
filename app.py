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
import re
import uuid
from contextlib import contextmanager
import datetime as dt
from decimal import Decimal
from functools import wraps
from xml.etree import ElementTree as ET

import threading

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
_POOL_MAX = int(os.environ.get("DB_POOL_MAX", "4"))
_pool = None
_pool_lock = threading.Lock()
_pool_cupo = threading.BoundedSemaphore(_POOL_MAX)


def _crear_conn():
    extra = {"sslmode": os.environ["DB_SSLMODE"]} if os.environ.get("DB_SSLMODE") else {}
    return psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor, **extra)


def get_conn():
    """Conexión reutilizada de un pool. Abrir una conexión SSL nueva a Supabase en cada
    petición costaba cerca de un segundo; reutilizarla hace las respuestas mucho más rápidas."""
    global _pool
    with _pool_lock:
        if _pool is None:
            _pool = []
    _pool_cupo.acquire()  # espera si ya hay _POOL_MAX conexiones en uso
    try:
        while True:
            with _pool_lock:
                conn = _pool.pop() if _pool else None
            if conn is None:
                return _crear_conn()
            try:
                if conn.closed:
                    continue
                with conn.cursor() as c:  # comprueba que la conexión sigue viva
                    c.execute("select 1")
                conn.rollback()
                return conn
            except Exception:
                try:
                    conn.close()
                except Exception:
                    pass
    except Exception:
        _pool_cupo.release()
        raise


def soltar_conn(conn, descartar=False):
    try:
        if not descartar and not conn.closed:
            conn.rollback()
            with _pool_lock:
                _pool.append(conn)
        else:
            conn.close()
    except Exception:
        try:
            conn.close()
        except Exception:
            pass
    finally:
        _pool_cupo.release()


@contextmanager
def db():
    """Una transacción por petición: confirma al salir bien, deshace si hay error.
    La conexión vuelve al pool (o se descarta si quedó dañada)."""
    conn = get_conn()
    malo = False
    try:
        with conn:
            with conn.cursor() as cur:
                yield cur
    except (psycopg2.OperationalError, psycopg2.InterfaceError):
        malo = True
        raise
    finally:
        soltar_conn(conn, descartar=malo)


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


# ------------------------------------------------------------ reglas del avión y de precios
CAPACIDAD_MIN, CAPACIDAD_MAX = 6, 300     # asientos totales de un avión
MAX_PRIMERA, MAX_EJECUTIVA = 16, 48       # tope de asientos por cabina
MIN_ECONOMICA = 6                         # al menos una fila económica si hay otras cabinas
MAX_ESCALAS = 3
LETRAS = "ABCDEF"      # económica: A B C | pasillo | D E F
HOLD_SEGUNDOS = 300    # un asiento elegido queda retenido 5 minutos
MAX_ASIENTOS = 8       # máximo de asientos por reserva (por vuelo)
MAX_VUELOS_COMPRA = 6  # máximo de vuelos en una misma compra

# cabinas: letras por fila (el pasillo separa mitades), multiplicador de precio y equipaje incluido
CLASES = {
    "primera":   {"letras": "AF",     "por_fila": 2, "mult": Decimal("3.0"), "incluye": "bodega32"},
    "ejecutiva": {"letras": "ABEF",   "por_fila": 4, "mult": Decimal("2.0"), "incluye": "bodega23"},
    "economica": {"letras": "ABCDEF", "por_fila": 6, "mult": Decimal("1.0"), "incluye": "mano"},
}
EQUIPAJE = {"mano": Decimal("0"), "bodega23": Decimal("25"), "bodega32": Decimal("40")}
TIPOS_PASAJERO = ("adulto", "nino")
DESCUENTO_NINO = Decimal("0.25")


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
        if isinstance(c, bool) or not isinstance(c, int):
            return None, "capacidad debe ser un número entero"
        if not CAPACIDAD_MIN <= c <= CAPACIDAD_MAX:
            return None, f"La capacidad debe estar entre {CAPACIDAD_MIN} y {CAPACIDAD_MAX} asientos"
        out["capacidad"] = c
    for campo, tope, multiplo, nombre in (
            ("asientos_primera", MAX_PRIMERA, 2, "primera clase"),
            ("asientos_ejecutiva", MAX_EJECUTIVA, 4, "clase ejecutiva")):
        if campo in d or not parcial:
            n = d.get(campo, 0)
            if isinstance(n, bool) or not isinstance(n, int) or n < 0:
                return None, f"{campo} debe ser un entero >= 0"
            if n > tope:
                return None, f"{nombre.capitalize()}: máximo {tope} asientos"
            if n % multiplo:
                return None, f"{nombre.capitalize()}: los asientos van de a {multiplo} por fila (múltiplo de {multiplo})"
            out[campo] = n
    if "escalas" in d or not parcial:
        e = d.get("escalas", 0)
        if isinstance(e, bool) or not isinstance(e, int) or not 0 <= e <= MAX_ESCALAS:
            return None, f"escalas debe ser un entero entre 0 y {MAX_ESCALAS}"
        out["escalas"] = e
    if "ciudades_escala" in d or "escalas" in out:
        ciudades = str(d.get("ciudades_escala") or "").strip()
        if out.get("escalas", 1) == 0:
            ciudades = ""
        elif "escalas" in out and not ciudades:
            return None, "Indica las ciudades de escala"
        if len(ciudades) > 200:
            return None, "ciudades_escala es demasiado largo"
        out["ciudades_escala"] = ciudades
    if "origen" in out and "destino" in out and out["origen"].lower() == out["destino"].lower():
        return None, "El origen y el destino no pueden ser iguales"
    return out, None


def validar_distribucion(capacidad, primera, ejecutiva):
    """Devuelve un mensaje de error si las cabinas no caben en el avión."""
    economica = capacidad - primera - ejecutiva
    if economica < 0:
        return "Primera clase + ejecutiva no pueden superar la capacidad total"
    if (primera or ejecutiva) and economica < MIN_ECONOMICA:
        return f"Debe quedar al menos {MIN_ECONOMICA} asientos en clase económica"
    return None


def diseno_asientos(primera, ejecutiva, economica):
    """Lista (fila, letra, codigo, clase) de todo el avión: primero primera clase al frente,
    luego ejecutiva y al final económica. Las filas se numeran seguidas."""
    res, base = [], 0
    for clase, n in (("primera", primera), ("ejecutiva", ejecutiva), ("economica", economica)):
        k, letras = CLASES[clase]["por_fila"], CLASES[clase]["letras"]
        for i in range(n):
            fila, letra = base + i // k + 1, letras[i % k]
            res.append((fila, letra, f"{fila}{letra}", clase))
        base += -(-n // k)
    return res


def precio_asiento(precio_vuelo, clase, tipo, equipaje):
    """Precio SIN IVA de un pasajero: tarifa según la cabina, descuento de niño y el equipaje
    que exceda lo que ya incluye la cabina."""
    base = Decimal(precio_vuelo) * CLASES[clase]["mult"]
    if tipo == "nino":
        base = base * (1 - DESCUENTO_NINO)
    extra = max(Decimal("0"), EQUIPAJE[equipaje] - EQUIPAJE[CLASES[clase]["incluye"]])
    return (base + extra).quantize(Decimal("0.01"))


def con_iva(monto):
    return (Decimal(monto) * (1 + IVA)).quantize(Decimal("0.01"))


# ------------------------------------------------------------ asientos y concurrencia
def ordenar(codigos):
    return sorted(codigos, key=lambda c: (int(c[:-1]), c[-1]))


def crear_asientos(cur, vuelo_id, primera, ejecutiva, economica):
    """Crea todos los asientos de un vuelo nuevo."""
    filas = [(vuelo_id, f, l, c, cl) for f, l, c, cl in diseno_asientos(primera, ejecutiva, economica)]
    if filas:
        psycopg2.extras.execute_values(
            cur, "insert into asientos_vuelo (vuelo_id, fila, letra, codigo, clase) values %s", filas)


def agregar_economicos(cur, vuelo_id, cantidad, primera, ejecutiva, existentes):
    """Agrega `cantidad` asientos económicos nuevos al final saltando los códigos que ya existen."""
    base = primera // 2 + ejecutiva // 4
    filas, i = [], 0
    while len(filas) < cantidad:
        fila, letra = base + i // 6 + 1, LETRAS[i % 6]
        if f"{fila}{letra}" not in existentes:
            filas.append((vuelo_id, fila, letra, f"{fila}{letra}", "economica"))
        i += 1
    if filas:
        psycopg2.extras.execute_values(
            cur, "insert into asientos_vuelo (vuelo_id, fila, letra, codigo, clase) values %s", filas)


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
        "select id, codigo, clase, estado, reserva_id, retenido_por, tipo_pasajero, equipaje, "
        "precio_pagado, coalesce(retenido_hasta > now(), false) as retenido_activo "
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


class ConflictoAsientos(Exception):
    """Se lanza dentro de una transacción: Flask responde 404/409 y la BD deshace todo."""
    def __init__(self, inexistentes, no_disponibles, vuelo_id=None):
        self.inexistentes, self.no_disponibles, self.vuelo_id = inexistentes, no_disponibles, vuelo_id


@app.errorhandler(ConflictoAsientos)
def _conflicto_asientos(e):
    return respuesta_conflicto(e.inexistentes, e.no_disponibles)


def asientos_auto(cur, vuelo_id, cantidad, usuario_id, excluir=()):
    """Elige `cantidad` asientos ECONÓMICOS libres (sin retención ajena) y los bloquea."""
    cur.execute(
        "select codigo from asientos_vuelo where vuelo_id = %s and estado = 'libre' "
        "and clase = 'economica' "
        "and (retenido_hasta is null or retenido_hasta <= now() or retenido_por = %s) "
        "and not (codigo = any(%s::varchar[])) order by fila, letra limit %s for update",
        (vuelo_id, usuario_id, list(excluir), cantidad))
    return [f["codigo"] for f in cur.fetchall()]


def normalizar_pasajeros(lista, maximo=MAX_ASIENTOS):
    """Valida los pasajeros de un vuelo: [{"asiento":"3A","tipo":"adulto","equipaje":"mano"}].
    Reglas: 1 a 8 pasajeros, sin asientos repetidos y todo niño viaja con al menos un adulto.
    Devuelve (lista_normalizada, mensaje_de_error)."""
    if not isinstance(lista, list) or not lista:
        return None, "Elige al menos un asiento"
    if len(lista) > maximo:
        return None, f"Máximo {maximo} asientos por vuelo"
    out, vistos = [], set()
    for p in lista:
        if isinstance(p, str):
            p = {"asiento": p}
        if not isinstance(p, dict):
            return None, "Cada pasajero debe indicar su asiento"
        codigos, msg = normalizar_codigos([p.get("asiento")] if isinstance(p.get("asiento"), str) else None)
        if msg or len(codigos) != 1:
            return None, msg or "Código de asiento inválido"
        codigo = codigos[0]
        if codigo in vistos:
            return None, f"El asiento {codigo} está repetido"
        vistos.add(codigo)
        tipo = str(p.get("tipo") or "adulto").lower()
        if tipo == "niño":
            tipo = "nino"
        if tipo not in TIPOS_PASAJERO:
            return None, "tipo debe ser 'adulto' o 'nino'"
        equipaje = str(p.get("equipaje") or "mano")
        if equipaje not in EQUIPAJE:
            return None, "equipaje debe ser 'mano', 'bodega23' o 'bodega32'"
        out.append({"asiento": codigo, "tipo": tipo, "equipaje": equipaje})
    if any(p["tipo"] == "nino" for p in out) and not any(p["tipo"] == "adulto" for p in out):
        return None, "Un niño debe viajar acompañado de al menos un adulto"
    out.sort(key=lambda p: (int(p["asiento"][:-1]), p["asiento"][-1]))
    return out, None


def actualizar_asientos_reservados(cur, vuelo_id, reserva_id, filas):
    """filas: [(codigo, tipo, equipaje, precio)] -> marca esos asientos como reservados."""
    valores = b",".join(
        cur.mogrify("(%s::varchar, %s::varchar, %s::varchar, %s::numeric)", f) for f in filas)
    cur.execute(
        b"update asientos_vuelo a set estado = 'reservado', reserva_id = %d, "
        b"retenido_por = null, retenido_hasta = null, tipo_pasajero = v.tipo, "
        b"equipaje = v.equipaje, precio_pagado = v.precio from (values %s) "
        b"as v(codigo, tipo, equipaje, precio) where a.vuelo_id = %d and a.codigo = v.codigo"
        % (int(reserva_id), valores, int(vuelo_id)))


def reservar_en_vuelo(cur, vuelo, pasajeros, usuario_id, compra_id=None):
    """Compra los asientos de UN vuelo (el vuelo ya debe estar bloqueado con FOR UPDATE).
    Todo o nada: si un asiento no está disponible lanza ConflictoAsientos."""
    codigos = [p["asiento"] for p in pasajeros]
    filas = bloquear_asientos(cur, vuelo["id"], codigos, usuario_id)
    inexistentes, no_disponibles = conflictos_asientos(filas, codigos, usuario_id)
    if inexistentes or no_disponibles:
        raise ConflictoAsientos(inexistentes, no_disponibles, vuelo["id"])
    clase_de = {f["codigo"]: f["clase"] for f in filas}
    detalle = [(p["asiento"], p["tipo"], p["equipaje"],
                precio_asiento(vuelo["precio"], clase_de[p["asiento"]], p["tipo"], p["equipaje"]))
               for p in pasajeros]
    subtotal = sum((d[3] for d in detalle), Decimal("0"))
    cur.execute(
        "insert into reservas (usuario_id, vuelo_id, cantidad_asientos, total, estado, compra_id) "
        "values (%s, %s, %s, %s, 'confirmada', %s) returning id, total, estado",
        (usuario_id, vuelo["id"], len(detalle), subtotal, compra_id))
    r = cur.fetchone()
    actualizar_asientos_reservados(cur, vuelo["id"], r["id"], detalle)
    cur.execute("update asientos_vuelo set retenido_por = null, retenido_hasta = null "
                "where vuelo_id = %s and retenido_por = %s", (vuelo["id"], usuario_id))
    cur.execute("update vuelos set asientos_disponibles = asientos_disponibles - %s where id = %s",
                (len(detalle), vuelo["id"]))
    cur.execute(
        "insert into pagos (usuario_id, compra_id, reserva_id, tipo, monto, detalle) "
        "values (%s, %s, %s, 'cobro', %s, %s)",
        (usuario_id, compra_id, r["id"], con_iva(subtotal),
         f"Compra {vuelo['origen']} - {vuelo['destino']} ({len(detalle)} asiento(s))"))
    return {"reserva_id": r["id"], "vuelo_id": vuelo["id"], "subtotal": subtotal,
            "total_con_iva": con_iva(subtotal), "asientos": ordenar(codigos),
            "pasajeros": [{"asiento": d[0], "clase": clase_de[d[0]], "tipo": d[1],
                           "equipaje": d[2], "valor": float(d[3])} for d in detalle]}


def mapa_asientos(cur, vuelo_id, usuario_id, editar_reserva_id=None):
    """Estado del avión desde el punto de vista de `usuario_id`:
    libre | ocupado (comprado) | retenido (lo eligió otra persona) | mio (lo eligió él).
    Con `editar_reserva_id`, los asientos de esa reserva (suya) aparecen como 'mio'."""
    cur.execute("select * from vuelos where id = %s", (vuelo_id,))
    v = cur.fetchone()
    cur.execute(
        "select codigo, fila, letra, clase, "
        "case when estado = 'reservado' and reserva_id = %s then 'mio' "
        "     when estado = 'reservado' then 'ocupado' "
        "     when coalesce(retenido_hasta > now(), false) and retenido_por = %s then 'mio' "
        "     when coalesce(retenido_hasta > now(), false) then 'retenido' "
        "     else 'libre' end as estado, "
        "case when estado = 'libre' and coalesce(retenido_hasta > now(), false) and retenido_por = %s "
        "     then greatest(0, extract(epoch from (retenido_hasta - now())))::int end as segundos "
        "from asientos_vuelo where vuelo_id = %s order by fila, letra",
        (editar_reserva_id, usuario_id, usuario_id, vuelo_id))
    filas = cur.fetchall()
    segundos = [f["segundos"] for f in filas if f["segundos"] is not None]
    return {
        "vuelo_id": vuelo_id,
        "hold_segundos": HOLD_SEGUNDOS,
        "expira_en": min(segundos) if segundos else None,
        "max_asientos": MAX_ASIENTOS,
        "vuelo": {"precio": float(v["precio"]), "escalas": v["escalas"],
                  "ciudades_escala": v["ciudades_escala"],
                  "primera": v["asientos_primera"], "ejecutiva": v["asientos_ejecutiva"],
                  "economica": v["capacidad"] - v["asientos_primera"] - v["asientos_ejecutiva"]},
        "tarifas": {c: {"multiplicador": float(i["mult"]), "equipaje_incluido": i["incluye"],
                        "precio": float((Decimal(v["precio"]) * i["mult"]).quantize(Decimal("0.01")))}
                    for c, i in CLASES.items()},
        "equipaje": {k: float(x) for k, x in EQUIPAJE.items()},
        "descuento_nino": float(DESCUENTO_NINO),
        "asientos": [{"codigo": f["codigo"], "fila": f["fila"], "letra": f["letra"],
                      "clase": f["clase"], "estado": f["estado"]} for f in filas],
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
def listar_vuelos():
    # El catálogo es público para que se pueda consultar antes de autenticarse.
    filtros, params = [], []
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
    msg = validar_distribucion(datos["capacidad"], datos["asientos_primera"], datos["asientos_ejecutiva"])
    if msg:
        return error(msg)
    with db() as cur:
        cur.execute(
            "insert into vuelos (origen, destino, fecha, hora_salida, hora_llegada, precio, "
            "capacidad, asientos_disponibles, asientos_primera, asientos_ejecutiva, escalas, "
            "ciudades_escala) values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) returning *",
            (datos["origen"], datos["destino"], datos["fecha"], datos["hora_salida"],
             datos["hora_llegada"], datos["precio"], datos["capacidad"], datos["capacidad"],
             datos["asientos_primera"], datos["asientos_ejecutiva"], datos["escalas"],
             datos["ciudades_escala"]),
        )
        v = cur.fetchone()
        crear_asientos(cur, v["id"], v["asientos_primera"], v["asientos_ejecutiva"],
                       v["capacidad"] - v["asientos_primera"] - v["asientos_ejecutiva"])
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
        primera, ejecutiva = actual["asientos_primera"], actual["asientos_ejecutiva"]
        if datos.get("asientos_primera", primera) != primera or \
                datos.get("asientos_ejecutiva", ejecutiva) != ejecutiva:
            return error("Los asientos de primera clase y ejecutiva no se pueden cambiar una vez "
                         "creado el vuelo (solo la capacidad económica)", 409)
        datos.pop("asientos_primera", None)
        datos.pop("asientos_ejecutiva", None)
        # asientos ya vendidos = capacidad anterior - disponibles
        vendidos = actual["capacidad"] - actual["asientos_disponibles"]
        capacidad = datos.get("capacidad", actual["capacidad"])
        if capacidad < vendidos:
            return error(f"La capacidad no puede ser menor a los {vendidos} asientos ya reservados", 409)
        msg = validar_distribucion(capacidad, primera, ejecutiva)
        if msg:
            return error(msg)
        datos["asientos_disponibles"] = capacidad - vendidos
        if capacidad > actual["capacidad"]:
            cur.execute("select codigo from asientos_vuelo where vuelo_id = %s", (vuelo_id,))
            agregar_economicos(cur, vuelo_id, capacidad - actual["capacidad"], primera, ejecutiva,
                               {f["codigo"] for f in cur.fetchall()})
        elif capacidad < actual["capacidad"]:
            # se quitan los últimos asientos económicos LIBRES (los comprados nunca se tocan)
            quitar = actual["capacidad"] - capacidad
            cur.execute(
                "delete from asientos_vuelo where id in (select id from asientos_vuelo "
                "where vuelo_id = %s and estado = 'libre' and clase = 'economica' "
                "order by fila desc, letra desc limit %s) returning id", (vuelo_id, quitar))
            if cur.rowcount < quitar:
                raise ReduccionImposible()
        columnas = ", ".join(f"{k} = %s" for k in datos)
        cur.execute(f"update vuelos set {columnas} where id = %s returning *",
                    (*datos.values(), vuelo_id))
        v = cur.fetchone()
    return responder({"mensaje": "Vuelo actualizado", "vuelo": fila_a_dict(v)})


class ReduccionImposible(Exception):
    pass


@app.errorhandler(ReduccionImposible)
def _reduccion_imposible(e):
    return error("No hay suficientes asientos económicos libres para reducir la capacidad", 409)


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
        editar = request.args.get("reserva_id", type=int)
        if editar is not None:
            cur.execute("select 1 from reservas where id = %s and usuario_id = %s and vuelo_id = %s "
                        "and estado = 'confirmada'", (editar, g.usuario_id, vuelo_id))
            if not cur.fetchone():
                editar = None
        mapa = mapa_asientos(cur, vuelo_id, g.usuario_id, editar)
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


# ------------------------------------------------------------ datos de facturación y perfil
RE_CORREO = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]{2,}$")
RE_NOMBRE = re.compile(r"^[A-Za-zÁÉÍÓÚÜÑáéíóúüñ][A-Za-zÁÉÍÓÚÜÑáéíóúüñ' .-]{1,59}$")


def cedula_valida(c):
    """Cédula ecuatoriana: 10 dígitos, provincia 01-24 o 30, tercer dígito < 6 y dígito
    verificador (módulo 10)."""
    if not (c.isdigit() and len(c) == 10):
        return False
    provincia = int(c[:2])
    if not (1 <= provincia <= 24 or provincia == 30) or int(c[2]) >= 6:
        return False
    suma = 0
    for i in range(9):
        n = int(c[i]) * (2 if i % 2 == 0 else 1)
        suma += n - 9 if n > 9 else n
    return (10 - suma % 10) % 10 == int(c[9])


def validar_facturacion(f):
    """Valida los datos de la factura. Devuelve (datos, mensaje_de_error)."""
    if not isinstance(f, dict):
        return None, "Faltan los datos de facturación"
    out = {}
    for campo, etiqueta in (("nombres", "Nombres"), ("apellidos", "Apellidos")):
        v = " ".join(str(f.get(campo) or "").split())
        if not RE_NOMBRE.match(v):
            return None, f"{etiqueta}: solo letras, entre 2 y 60 caracteres"
        out[campo] = v
    tipo = str(f.get("tipo_documento") or "").lower()
    if tipo not in ("cedula", "pasaporte"):
        return None, "tipo_documento debe ser 'cedula' o 'pasaporte'"
    doc = str(f.get("documento") or "").strip().upper()
    if tipo == "cedula" and not cedula_valida(doc):
        return None, "La cédula no es válida (10 dígitos de una cédula ecuatoriana)"
    if tipo == "pasaporte" and not re.fullmatch(r"[A-Z0-9]{5,20}", doc):
        return None, "El pasaporte debe tener entre 5 y 20 letras o números"
    out["tipo_documento"], out["documento"] = tipo, doc
    correo = str(f.get("correo") or "").strip().lower()
    if not RE_CORREO.match(correo) or len(correo) > 160:
        return None, "El correo no es válido"
    out["correo"] = correo
    direccion = " ".join(str(f.get("direccion") or "").split())
    if not 5 <= len(direccion) <= 200:
        return None, "La dirección debe tener entre 5 y 200 caracteres"
    out["direccion"] = direccion
    return out, None


def facturacion_de_usuario(u):
    return {"nombres": u["nombres"], "apellidos": u["apellidos"],
            "tipo_documento": u["tipo_documento"], "documento": u["documento"],
            "correo": u["correo_facturacion"], "direccion": u["direccion"]}


def guardar_facturacion_en_perfil(cur, usuario_id, d):
    cur.execute(
        "update usuarios set nombres = %s, apellidos = %s, tipo_documento = %s, documento = %s, "
        "correo_facturacion = %s, direccion = %s where id = %s",
        (d["nombres"], d["apellidos"], d["tipo_documento"], d["documento"], d["correo"],
         d["direccion"], usuario_id))


@app.get("/api/perfil")
@requiere_token
def ver_perfil():
    with db() as cur:
        cur.execute("select * from usuarios where id = %s", (g.usuario_id,))
        u = cur.fetchone()
    return responder({"usuario": {"id": u["id"], "nombre": u["nombre"], "correo": u["correo"],
                                  "rol": u["rol"]},
                      "facturacion": facturacion_de_usuario(u)}, raiz="perfil")


@app.put("/api/perfil")
@requiere_token
def guardar_perfil():
    """Guarda los datos de facturación para futuras compras."""
    datos, msg = validar_facturacion(request.get_json(silent=True) or {})
    if msg:
        return error(msg)
    with db() as cur:
        guardar_facturacion_en_perfil(cur, g.usuario_id, datos)
    return responder({"mensaje": "Datos de facturación guardados", "facturacion": datos})


# ------------------------------------------------------------------ compras (varios vuelos)
def normalizar_items(items):
    """items: [{"vuelo_id": 1, "pasajeros": [...]}] -> ordenados por vuelo (orden de bloqueo)."""
    if not isinstance(items, list) or not items:
        return None, "El carrito está vacío"
    if len(items) > MAX_VUELOS_COMPRA:
        return None, f"Máximo {MAX_VUELOS_COMPRA} vuelos por compra"
    out, vistos = [], set()
    for it in items:
        vid = it.get("vuelo_id") if isinstance(it, dict) else None
        if not isinstance(vid, int) or isinstance(vid, bool):
            return None, "Cada vuelo del carrito debe indicar vuelo_id"
        if vid in vistos:
            return None, f"El vuelo {vid} está repetido en la compra"
        vistos.add(vid)
        pas, msg = normalizar_pasajeros(it.get("pasajeros"))
        if msg:
            return None, msg
        out.append({"vuelo_id": vid, "pasajeros": pas})
    out.sort(key=lambda x: x["vuelo_id"])
    return out, None


def resumen_totales(subtotal):
    iva = (subtotal * IVA).quantize(Decimal("0.01"))
    return {"subtotal": float(subtotal), "iva": float(iva), "total": float(subtotal + iva)}


@app.post("/api/cotizar")
@requiere_token
def cotizar():
    """Precio exacto del carrito (lo calcula el servidor; el cliente solo lo muestra)."""
    items, msg = normalizar_items((request.get_json(silent=True) or {}).get("items"))
    if msg:
        return error(msg)
    total, salida = Decimal("0"), []
    with db() as cur:
        for it in items:
            cur.execute("select * from vuelos where id = %s", (it["vuelo_id"],))
            v = cur.fetchone()
            if not v:
                return error(f"Vuelo {it['vuelo_id']} no encontrado", 404)
            codigos = [p["asiento"] for p in it["pasajeros"]]
            cur.execute(
                "select codigo, clase, estado, reserva_id, retenido_por, "
                "coalesce(retenido_hasta > now(), false) as retenido_activo "
                "from asientos_vuelo where vuelo_id = %s and codigo = any(%s::varchar[])",
                (v["id"], codigos))
            filas = cur.fetchall()
            inexistentes, no_disp = conflictos_asientos(filas, codigos, g.usuario_id)
            if inexistentes or no_disp:
                return respuesta_conflicto(inexistentes, no_disp)
            clase_de = {f["codigo"]: f["clase"] for f in filas}
            lineas = [{"asiento": p["asiento"], "clase": clase_de[p["asiento"]], "tipo": p["tipo"],
                       "equipaje": p["equipaje"],
                       "valor": float(precio_asiento(v["precio"], clase_de[p["asiento"]],
                                                     p["tipo"], p["equipaje"]))}
                      for p in it["pasajeros"]]
            sub = sum((Decimal(str(x["valor"])) for x in lineas), Decimal("0"))
            total += sub
            salida.append({"vuelo_id": v["id"], "ruta": f"{v['origen']} - {v['destino']}",
                           "fecha": v["fecha"].isoformat(), "pasajeros": lineas,
                           "subtotal": float(sub)})
    return responder({"items": salida, **resumen_totales(total)}, raiz="cotizacion")


@app.post("/api/compras")
@requiere_token
def crear_compra():
    """Compra de uno o varios vuelos con una sola factura. Todo o nada:
    si un asiento de cualquier vuelo ya no está disponible, no se compra nada.
    {"facturacion": {...}, "guardar_perfil": true,
     "items": [{"vuelo_id": 1, "pasajeros": [{"asiento":"3A","tipo":"adulto","equipaje":"mano"}]}]}"""
    d = request.get_json(silent=True) or {}
    fact, msg = validar_facturacion(d.get("facturacion"))
    if msg:
        return error(msg)
    items, msg = normalizar_items(d.get("items"))
    if msg:
        return error(msg)
    with db() as cur:
        # 1) se bloquean TODOS los vuelos en orden de id; 2) luego los asientos de cada vuelo en
        #    ese mismo orden: dos compras cruzadas nunca se esperan en círculo (sin interbloqueos).
        ids = [it["vuelo_id"] for it in items]
        cur.execute("select * from vuelos where id = any(%s) order by id for update", (ids,))
        vuelos = {v["id"]: v for v in cur.fetchall()}
        faltan = [i for i in ids if i not in vuelos]
        if faltan:
            return error(f"Vuelo {faltan[0]} no encontrado", 404)
        cur.execute(
            "insert into compras (usuario_id, nombres, apellidos, tipo_documento, documento, "
            "correo, direccion) values (%s, %s, %s, %s, %s, %s, %s) returning id, fecha",
            (g.usuario_id, fact["nombres"], fact["apellidos"], fact["tipo_documento"],
             fact["documento"], fact["correo"], fact["direccion"]))
        compra = cur.fetchone()
        reservas = [reservar_en_vuelo(cur, vuelos[it["vuelo_id"]], it["pasajeros"],
                                      g.usuario_id, compra["id"]) for it in items]
        if d.get("guardar_perfil", True):
            guardar_facturacion_en_perfil(cur, g.usuario_id, fact)
    subtotal = sum((r["subtotal"] for r in reservas), Decimal("0"))
    for r in reservas:
        r["subtotal"] = float(r["subtotal"])
        r["total_con_iva"] = float(r["total_con_iva"])
    return responder({"mensaje": "Compra realizada", "compra_id": compra["id"],
                      **resumen_totales(subtotal), "reservas": reservas}, 201)


# ---------------------------------------------------------------------- reservas
@app.post("/api/reservas")
@requiere_token
def crear_reserva():
    """Reserva rápida de UN vuelo sin factura (se mantiene por compatibilidad):
    {"vuelo_id": 1, "asientos": ["3A","3B"]} o {"vuelo_id": 1, "cantidad": 2} (económica).
    La compra completa (varios vuelos, factura, equipaje) es POST /api/compras."""
    d = request.get_json(silent=True) or {}
    vuelo_id, cantidad = d.get("vuelo_id"), d.get("cantidad")
    if not isinstance(vuelo_id, int) or isinstance(vuelo_id, bool):
        return error("vuelo_id es obligatorio")
    pasajeros = None
    if d.get("pasajeros") is not None or d.get("asientos") is not None:
        pasajeros, msg = normalizar_pasajeros(d.get("pasajeros") if d.get("pasajeros") is not None
                                              else d["asientos"])
        if msg:
            return error(msg)
    elif not (isinstance(cantidad, int) and not isinstance(cantidad, bool)
              and 1 <= cantidad <= MAX_ASIENTOS):
        return error('Indica los asientos (asientos: ["1A","1B"]) o la cantidad de pasajeros (1 a 8)')

    with db() as cur:
        cur.execute("select * from vuelos where id = %s for update", (vuelo_id,))
        vuelo = cur.fetchone()
        if not vuelo:
            return error("Vuelo no encontrado", 404)
        if pasajeros is None:
            bloquear_asientos(cur, vuelo_id, [], g.usuario_id)
            codigos = asientos_auto(cur, vuelo_id, cantidad, g.usuario_id)
            if len(codigos) < cantidad:
                return error("No hay asientos suficientes", 409)
            pasajeros, _ = normalizar_pasajeros(codigos)
        r = reservar_en_vuelo(cur, vuelo, pasajeros, g.usuario_id)
    return responder(
        {"mensaje": "Reserva creada", "reserva_id": r["reserva_id"], "total": float(r["subtotal"]),
         "total_con_iva": float(r["total_con_iva"]), "estado": "confirmada",
         "asientos": r["asientos"]}, 201)


SQL_RESERVA = """
select r.id, r.usuario_id, r.vuelo_id, r.cantidad_asientos, r.total, r.estado,
       r.fecha_reserva, r.compra_id, v.origen, v.destino, v.fecha, v.hora_salida, v.hora_llegada,
       v.precio, v.escalas, v.ciudades_escala, u.nombre as cliente,
       (select string_agg(a.codigo, ',' order by a.fila, a.letra)
          from asientos_vuelo a where a.reserva_id = r.id) as asientos,
       (select coalesce(json_agg(json_build_object('asiento', a.codigo, 'clase', a.clase,
                'tipo', a.tipo_pasajero, 'equipaje', a.equipaje, 'valor', a.precio_pagado)
                order by a.fila, a.letra), '[]'::json)
          from asientos_vuelo a where a.reserva_id = r.id) as pasajeros
from reservas r
join vuelos v on v.id = r.vuelo_id
join usuarios u on u.id = r.usuario_id
"""


def reserva_a_dict(r):
    d = fila_a_dict(r)
    d["total_con_iva"] = float(con_iva(r["total"]))
    return d


@app.get("/api/reservas")
@requiere_token
def listar_reservas():
    with db() as cur:
        cur.execute(SQL_RESERVA + " where r.usuario_id = %s order by r.fecha_reserva desc, r.id desc",
                    (g.usuario_id,))
        filas = [reserva_a_dict(f) for f in cur.fetchall()]
    return responder({"reservas": filas}, raiz="reservas")


def obtener_reserva(cur, reserva_id):
    cur.execute(SQL_RESERVA + " where r.id = %s and r.usuario_id = %s",
                (reserva_id, g.usuario_id))
    return cur.fetchone()


def movimientos_de(cur, reserva_id):
    cur.execute("select tipo, monto, detalle, fecha from pagos where reserva_id = %s "
                "order by fecha, id", (reserva_id,))
    return [fila_a_dict(m) for m in cur.fetchall()]


@app.get("/api/reservas/<int:reserva_id>")
@requiere_token
def ver_reserva(reserva_id):
    with db() as cur:
        r = obtener_reserva(cur, reserva_id)
        if not r:
            return error("Reserva no encontrada", 404)
        d = reserva_a_dict(r)
        d["movimientos"] = movimientos_de(cur, reserva_id)
    return responder(d, raiz="reserva")


def pasajeros_pedidos(d, actuales):
    """Convierte lo que envía el cliente en la lista objetivo de pasajeros de la reserva.
    `actuales` = {codigo: fila} de los asientos que hoy tiene. Acepta:
      {"pasajeros": [...]}  (completo: asiento, tipo, equipaje)
      {"asientos": [...]}   (conserva tipo/equipaje de los que ya tenía)
      {"cantidad": n}       (deja los primeros n; si faltan, agrega económicos libres)
    Devuelve (objetivo, mensaje_de_error, cantidad)."""
    if d.get("pasajeros") is not None:
        objetivo, msg = normalizar_pasajeros(d["pasajeros"])
        return objetivo, msg, None
    if d.get("asientos") is not None:
        codigos, msg = normalizar_codigos(d["asientos"])
        if msg or not codigos:
            return None, msg or "Elige al menos un asiento", None
        base = [{"asiento": c, "tipo": (actuales.get(c) or {}).get("tipo_pasajero") or "adulto",
                 "equipaje": (actuales.get(c) or {}).get("equipaje") or "mano"} for c in codigos]
        objetivo, msg = normalizar_pasajeros(base)
        return objetivo, msg, None
    n = d.get("cantidad")
    if isinstance(n, int) and not isinstance(n, bool) and 1 <= n <= MAX_ASIENTOS:
        return None, None, n
    return None, "Indica pasajeros (lista), asientos (lista) o cantidad (entero entre 1 y 8)", None


@app.put("/api/reservas/<int:reserva_id>")
@requiere_token
def actualizar_reserva(reserva_id):
    """Edita la reserva: asientos, tipo de pasajero y equipaje.
    - Si el nuevo valor es MAYOR, solo se cobra la diferencia (cobro_extra).
    - Si es MENOR, se reembolsa la diferencia (reembolso).
    Con "solo_cotizar": true devuelve lo que pasaría sin aplicar nada."""
    d = request.get_json(silent=True) or {}
    solo_cotizar = bool(d.get("solo_cotizar"))
    with db() as cur:
        cur.execute("select vuelo_id from reservas where id = %s and usuario_id = %s",
                    (reserva_id, g.usuario_id))
        fila = cur.fetchone()
        if not fila:
            return error("Reserva no encontrada", 404)
        vuelo_id = fila["vuelo_id"]
        cur.execute("select * from vuelos where id = %s for update", (vuelo_id,))
        vuelo = cur.fetchone()
        r = obtener_reserva(cur, reserva_id)          # se lee DESPUÉS de bloquear el vuelo
        if r["estado"] != "confirmada":
            return error("Solo se pueden modificar reservas confirmadas", 409)

        pedido = d.get("pasajeros") if d.get("pasajeros") is not None else d.get("asientos")
        pedidos = []
        if isinstance(pedido, list):
            for x in pedido:
                c = x.get("asiento") if isinstance(x, dict) else x
                if isinstance(c, str):
                    pedidos.append(c.strip().upper())
        filas = bloquear_asientos(cur, vuelo_id, pedidos, g.usuario_id, reserva_id)
        actuales = {f["codigo"]: f for f in filas if f["reserva_id"] == reserva_id}
        objetivo, msg, n = pasajeros_pedidos(d, actuales)
        if msg:
            return error(msg)
        if n is not None:                                  # modo "cantidad"
            ordenados = ordenar(list(actuales))
            if n <= len(ordenados):
                lista = ordenados[:n]
            else:
                extra = asientos_auto(cur, vuelo_id, n - len(ordenados), g.usuario_id, excluir=ordenados)
                if len(extra) < n - len(ordenados):
                    return error("No hay asientos suficientes", 409)
                lista = ordenados + extra
                filas = bloquear_asientos(cur, vuelo_id, lista, g.usuario_id, reserva_id)
            objetivo, msg = normalizar_pasajeros(
                [{"asiento": c, "tipo": (actuales.get(c) or {}).get("tipo_pasajero") or "adulto",
                  "equipaje": (actuales.get(c) or {}).get("equipaje") or "mano"} for c in lista])
        if msg:
            return error(msg)

        codigos = [p["asiento"] for p in objetivo]
        inexistentes, no_disponibles = conflictos_asientos(filas, codigos, g.usuario_id, reserva_id)
        if inexistentes or no_disponibles:
            return respuesta_conflicto(inexistentes, no_disponibles)
        clase_de = {f["codigo"]: f["clase"] for f in filas}
        detalle = []
        for p in objetivo:
            ant = actuales.get(p["asiento"])
            if ant and ant["tipo_pasajero"] == p["tipo"] and ant["equipaje"] == p["equipaje"] \
                    and ant["precio_pagado"] is not None:
                precio = ant["precio_pagado"]              # lo ya pagado no cambia
            else:
                precio = precio_asiento(vuelo["precio"], clase_de[p["asiento"]], p["tipo"], p["equipaje"])
            detalle.append((p["asiento"], p["tipo"], p["equipaje"], precio, clase_de[p["asiento"]]))
        nuevo_sub = sum((x[3] for x in detalle), Decimal("0"))
        viejo_sub = r["total"]
        diferencia = con_iva(nuevo_sub) - con_iva(viejo_sub)
        accion = "cobro_extra" if diferencia > 0 else "reembolso" if diferencia < 0 else "sin_cambio"
        resultado = {
            "reserva_id": reserva_id, "accion": accion, "monto": float(abs(diferencia)),
            "total_anterior": float(con_iva(viejo_sub)), "total_nuevo": float(con_iva(nuevo_sub)),
            "total": float(nuevo_sub), "asientos": ordenar(codigos),
            "pasajeros": [{"asiento": x[0], "clase": x[4], "tipo": x[1], "equipaje": x[2],
                           "valor": float(x[3])} for x in detalle]}
        if solo_cotizar:
            resultado["mensaje"] = "Cotización (no se aplicó ningún cambio)"
            return responder(resultado)

        quitar = [c for c in actuales if c not in codigos]
        agregar = [x for x in detalle if x[0] not in actuales]
        if quitar:
            cur.execute("update asientos_vuelo set estado = 'libre', reserva_id = null, "
                        "tipo_pasajero = null, equipaje = null, precio_pagado = null "
                        "where reserva_id = %s and codigo = any(%s::varchar[])", (reserva_id, quitar))
        actualizar_asientos_reservados(cur, vuelo_id, reserva_id, [x[:4] for x in detalle])
        cur.execute("update asientos_vuelo set retenido_por = null, retenido_hasta = null "
                    "where vuelo_id = %s and retenido_por = %s", (vuelo_id, g.usuario_id))
        cur.execute("update reservas set cantidad_asientos = %s, total = %s where id = %s",
                    (len(detalle), nuevo_sub, reserva_id))
        cur.execute("update vuelos set asientos_disponibles = asientos_disponibles + %s where id = %s",
                    (len(quitar) - len(agregar), vuelo_id))
        if accion != "sin_cambio":
            cur.execute(
                "insert into pagos (usuario_id, compra_id, reserva_id, tipo, monto, detalle) "
                "values (%s, %s, %s, %s, %s, %s)",
                (g.usuario_id, r["compra_id"], reserva_id, accion, abs(diferencia),
                 "Cambio de la reserva: " + ("cobro de la diferencia" if accion == "cobro_extra"
                                             else "reembolso de la diferencia")))
        resultado["mensaje"] = {"cobro_extra": "Reserva actualizada: se cobró solo la diferencia",
                                "reembolso": "Reserva actualizada: se reembolsa la diferencia",
                                "sin_cambio": "Reserva actualizada sin cambio de valor"}[accion]
    return responder(resultado)


@app.delete("/api/reservas/<int:reserva_id>")
@requiere_token
def cancelar_reserva(reserva_id):
    """Cancela la reserva, libera sus asientos y reembolsa lo pagado (con IVA)."""
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
                    "where id = %s and estado = 'confirmada' returning cantidad_asientos, total, compra_id",
                    (reserva_id,))
        r = cur.fetchone()
        if not r:
            return error("La reserva ya está cancelada", 409)
        cur.execute("update asientos_vuelo set estado = 'libre', reserva_id = null, "
                    "tipo_pasajero = null, equipaje = null, precio_pagado = null "
                    "where reserva_id = %s", (reserva_id,))
        liberados = cur.rowcount or r["cantidad_asientos"]
        cur.execute("update vuelos set asientos_disponibles = asientos_disponibles + %s "
                    "where id = %s", (liberados, vuelo_id))
        reembolso = con_iva(r["total"])
        cur.execute("insert into pagos (usuario_id, compra_id, reserva_id, tipo, monto, detalle) "
                    "values (%s, %s, %s, 'reembolso', %s, 'Cancelación de la reserva')",
                    (g.usuario_id, r["compra_id"], reserva_id, reembolso))
    return responder({"mensaje": "Reserva cancelada", "reserva_id": reserva_id,
                      "reembolso": float(reembolso)})


# ------------------------------------------------------------------------ factura XML
def xml_factura(compra, reservas, cliente):
    """Comprobante en XML (interoperabilidad). Los totales cuentan solo las reservas vigentes."""
    f = ET.Element("factura")
    ET.SubElement(f, "numero").text = f"P001-{compra['id']:06d}" if compra else f"P001-{reservas[0]['id']:06d}"
    fecha = compra["fecha"] if compra else reservas[0]["fecha_reserva"]
    ET.SubElement(f, "fecha").text = fecha.date().isoformat()
    c = ET.SubElement(f, "cliente")
    for k in ("nombres", "apellidos", "tipo_documento", "documento", "correo", "direccion"):
        ET.SubElement(c, k).text = cliente.get(k) or ""
    det = ET.SubElement(f, "detalle")
    subtotal = Decimal("0")
    for r in reservas:
        vigente = r["estado"] == "confirmada"
        v = ET.SubElement(det, "vuelo", reserva=str(r["id"]), estado=r["estado"])
        ET.SubElement(v, "ruta").text = f"{r['origen']} - {r['destino']}"
        ET.SubElement(v, "fecha_vuelo").text = r["fecha"].isoformat()
        ET.SubElement(v, "salida").text = r["hora_salida"].strftime("%H:%M")
        ET.SubElement(v, "llegada").text = r["hora_llegada"].strftime("%H:%M")
        ET.SubElement(v, "escalas").text = str(r["escalas"])
        ET.SubElement(v, "ciudades_escala").text = r["ciudades_escala"] or ""
        ps = ET.SubElement(v, "pasajeros")
        for p in (r["pasajeros"] or []):
            e = ET.SubElement(ps, "pasajero")
            for k in ("asiento", "clase", "tipo", "equipaje"):
                ET.SubElement(e, k).text = str(p.get(k) or "")
            ET.SubElement(e, "valor").text = f"{Decimal(str(p.get('valor') or 0)):.2f}"
        ET.SubElement(v, "subtotal").text = f"{r['total']:.2f}"
        if vigente:
            subtotal += r["total"]
    iva = (subtotal * IVA).quantize(Decimal("0.01"))
    ET.SubElement(f, "subtotal").text = f"{subtotal:.2f}"
    ET.SubElement(f, "iva").text = f"{iva:.2f}"
    ET.SubElement(f, "total").text = f"{subtotal + iva:.2f}"
    return Response(ET.tostring(f, encoding="utf-8", xml_declaration=True), mimetype="application/xml")


def factura_de_reservas(cur, compra_id, reserva_unica=None):
    if compra_id is not None:
        cur.execute("select * from compras where id = %s and usuario_id = %s", (compra_id, g.usuario_id))
        compra = cur.fetchone()
        if not compra:
            return None
        cur.execute(SQL_RESERVA + " where r.compra_id = %s order by r.vuelo_id", (compra_id,))
        return xml_factura(compra, cur.fetchall(), compra)
    r = reserva_unica
    return xml_factura(None, [r], {"nombres": r["cliente"]})


@app.get("/api/compras/<int:compra_id>/factura")
@requiere_token
def factura_compra(compra_id):
    with db() as cur:
        resp = factura_de_reservas(cur, compra_id)
    return resp or error("Compra no encontrada", 404)


@app.get("/api/reservas/<int:reserva_id>/factura")
@requiere_token
def factura_xml(reserva_id):
    """Factura de la reserva: la de su compra (con todos sus vuelos) o, si es una reserva
    rápida sin compra, un comprobante de ese vuelo."""
    with db() as cur:
        r = obtener_reserva(cur, reserva_id)
        if not r:
            return error("Reserva no encontrada", 404)
        resp = factura_de_reservas(cur, r["compra_id"], r)
    return resp


if __name__ == "__main__":
    # Solo desarrollo local. En Render se usa gunicorn (ver Procfile).
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")),
            debug=os.environ.get("FLASK_DEBUG", "1") == "1")
