# API de reservas de vuelos (Flask + Supabase)

## 1. Base de datos (Supabase > SQL Editor)
- **Proyecto nuevo (sin tablas):** ejecuta `schema.sql`.
- **Ya tienes las tablas creadas:** ejecuta `migracion.sql` (una sola vez). Agrega los roles y la
  capacidad de los vuelos sin borrar datos. **Hazlo antes de levantar la API actualizada.**
- **Mapa de asientos (nuevo):** si ya tenías tablas, ejecuta además `migracion_asientos.sql` (una sola vez;
  se puede repetir sin daño). Crea los asientos de cada vuelo y asigna asientos a las reservas existentes.
  **Hazlo antes de reiniciar la API.**

- **Versión 3 (clases, escalas, carrito, facturación, equipaje, editar reserva):** ejecuta `migracion_v3.sql`
  (una sola vez; es repetible). Requiere haber ejecutado antes `migracion.sql` y `migracion_asientos.sql`.
  Proyecto nuevo: `schema.sql` ya lo incluye. **Hazlo antes de reiniciar/redeplegar la API.**

## 2. Ejecutar la API
```bash
pip install -r requirements.txt
# crea el archivo .env con DATABASE_URL, JWT_SECRET y JWT_HORAS=2
python app.py                   # http://localhost:5000
```

## 3. Crear el primer administrador
El registro público (desde la app) **solo crea clientes**. El primer administrador se crea así:
```bash
# usuario nuevo
python crear_admin.py "Nombre Apellido" admin@mail.com clave123
# o convertir a un usuario que ya registraste desde la app (no cambia su contraseña)
python crear_admin.py correo@mail.com
```
Luego ese administrador puede crear más usuarios (clientes o administradores) desde la app.

## 4. Permisos por rol
| Acción | Cliente | Administrador |
|---|---|---|
| Registrarse, iniciar sesión | Sí | Sí |
| Buscar vuelos y reservar | Sí | Sí |
| Ver / cancelar sus reservas | Sí | Sí |
| Ver vuelos agotados | No | Sí |
| Crear, editar y eliminar vuelos (y su capacidad) | No (403) | Sí |
| Crear y listar usuarios | No (403) | Sí |

## 5. Endpoints
| Método | Ruta | Rol |
|---|---|---|
| POST | /api/usuarios/registro | público (crea cliente) |
| POST | /api/auth/login | público (devuelve token y rol) |
| GET | /api/vuelos?origen=&destino=&fecha= | cliente / admin |
| POST · PUT · DELETE | /api/vuelos · /api/vuelos/{id} | administrador |
| GET · POST | /api/usuarios | administrador |
| GET | /api/vuelos/{id}/asientos | cliente / admin (libre · ocupado · retenido · mio) |
| POST | /api/vuelos/{id}/asientos/retener `{"asientos":["3A","3B"]}` | cliente / admin |
| DELETE | /api/vuelos/{id}/asientos/retener | cliente / admin (suelta mi selección) |
| POST · GET | /api/reservas (`{"vuelo_id":1,"asientos":["3A","3B"]}`) | cliente / admin |
| GET · PUT · DELETE | /api/reservas/{id} | cliente / admin |
| GET · PUT | /api/perfil (datos de factura: nombres, apellidos, cédula/pasaporte, correo, dirección) | cliente / admin |
| POST | /api/cotizar `{"items":[{"vuelo_id":1,"pasajeros":[{"asiento":"3A","tipo":"adulto","equipaje":"bodega23"}]}]}` | cliente / admin |
| POST | /api/compras (varios vuelos, una factura; `facturacion`, `guardar_perfil`, `items`) | cliente / admin |
| PUT | /api/reservas/{id} `{"pasajeros":[...],"solo_cotizar":false}` → cobra solo la diferencia o reembolsa | cliente / admin |
| GET | /api/compras/{id}/factura · /api/reservas/{id}/factura | cliente / admin (XML de toda la compra) |

**Búsqueda:** `origen` y `destino` filtran por coincidencia parcial sin distinguir mayúsculas
(`quito` encuentra Quito). Si no hay resultados, la respuesta incluye `"mensaje": "Vuelo no encontrado"`.

**Capacidad:** al crear un vuelo, `capacidad` es el total de asientos y empieza todo disponible.
Al editarla no puede ser menor que los asientos ya reservados; los libres se recalculan solos.
Un vuelo con reservas no se puede eliminar.

## 5.1 Reglas de negocio (v3)
- **Capacidad:** 6 a 300 asientos por avión. **Primera clase:** 0–16 (de 2 en 2, 2 por fila, tarifa x3, maleta 32 kg incluida).
  **Ejecutiva:** 0–48 (de 4 en 4, 4 por fila, tarifa x2, maleta 23 kg incluida). **Económica:** el resto (mín. 6, 6 por fila).
  Primera y ejecutiva no se pueden cambiar con el vuelo ya creado.
- **Escalas:** 0 a 3 con las ciudades (obligatorias si hay escalas).
- **Pasajeros:** máx. 8 asientos por vuelo y 6 vuelos por compra. Cada pasajero es adulto o niño (25 % de descuento);
  un niño exige al menos un adulto en el mismo vuelo.
- **Equipaje:** mano $0, maleta 23 kg $25, maleta 32 kg $40 (se cobra lo que exceda lo incluido en la cabina).
- **Factura:** IVA 15 %. Los datos de factura se guardan en el perfil para futuras compras.
- **Editar reserva:** si el total nuevo es mayor se cobra solo la diferencia; si es menor se reembolsa la diferencia
  (queda registrado en el historial de pagos). Cancelar reembolsa el total pagado.
- Cédula ecuatoriana validada con su dígito verificador; el pasaporte acepta 5–20 caracteres alfanuméricos.

## 6. Concurrencia en la selección de asientos
- Cada asiento es una fila en `asientos_vuelo`; se bloquea con `SELECT ... FOR UPDATE` dentro de una transacción,
  así que dos personas no pueden quedarse con el mismo asiento (una recibe 201 y la otra 409).
- Al elegir, el asiento queda **retenido 5 minutos** (`retenido_por`, `retenido_hasta`); caduca solo.
- La retención y la compra son **todo o nada**: si uno de los asientos falla, no cambia ninguno.
- Orden de bloqueo fijo (vuelo, luego asientos por fila y letra) para evitar interbloqueos.
- Cancelar dos veces a la vez devuelve los asientos una sola vez.
- Máximo 8 asientos por reserva.

## 7. Probar con PowerShell
```powershell
$login = @{ correo = "admin@mail.com"; password = "clave123" } | ConvertTo-Json
$r = Invoke-RestMethod -Method Post -Uri http://localhost:5000/api/auth/login -ContentType "application/json" -Body $login
$h = @{ Authorization = "Bearer $($r.token)" }

# crear un vuelo (solo administrador)
$vuelo = @{ origen="Quito"; destino="Loja"; fecha="2026-12-01"; hora_salida="07:30"; hora_llegada="08:40"; precio=120.5; capacidad=60 } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri http://localhost:5000/api/vuelos -Headers $h -ContentType "application/json" -Body $vuelo

# buscar
Invoke-RestMethod -Uri "http://localhost:5000/api/vuelos?origen=Quito&destino=Loja" -Headers $h | ConvertTo-Json -Depth 5
```

Para el emulador Android de Flutter usa `http://10.0.2.2:5000`.
