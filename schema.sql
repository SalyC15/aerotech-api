-- Esquema para Supabase (PostgreSQL) - AeroTech, reservas de vuelos
-- Ejecutar en: Supabase > SQL Editor
-- (Si ya tienes las tablas creadas, usa migracion_v3.sql en lugar de este archivo)

create table if not exists usuarios (
    id             bigserial primary key,
    nombre         varchar(120) not null,
    correo         varchar(160) not null unique,
    password_hash  text not null,
    rol            varchar(20) not null default 'cliente'
                   check (rol in ('cliente','administrador')),
    fecha_registro timestamptz not null default now(),
    -- datos de facturación guardados en el perfil para futuras compras
    nombres            varchar(80),
    apellidos          varchar(80),
    tipo_documento     varchar(12) check (tipo_documento in ('cedula','pasaporte')),
    documento          varchar(20),
    correo_facturacion varchar(160),
    direccion          varchar(200)
);

create table if not exists vuelos (
    id                   bigserial primary key,
    origen               varchar(80) not null,
    destino              varchar(80) not null,
    fecha                date not null,
    hora_salida          time not null,
    hora_llegada         time not null,
    precio               numeric(10,2) not null check (precio >= 0),
    capacidad            integer not null check (capacidad >= 1),
    asientos_disponibles integer not null check (asientos_disponibles >= 0),
    asientos_primera     integer not null default 0 check (asientos_primera >= 0),
    asientos_ejecutiva   integer not null default 0 check (asientos_ejecutiva >= 0),
    escalas              integer not null default 0 check (escalas between 0 and 3),
    ciudades_escala      varchar(200) not null default '',
    check (asientos_disponibles <= capacidad),
    check (asientos_primera + asientos_ejecutiva <= capacidad)
);

-- Una compra = una factura; puede incluir varios vuelos (una reserva por vuelo)
create table if not exists compras (
    id               bigserial primary key,
    usuario_id       bigint not null references usuarios(id) on delete cascade,
    nombres          varchar(80) not null,
    apellidos        varchar(80) not null,
    tipo_documento   varchar(12) not null,
    documento        varchar(20) not null,
    correo           varchar(160) not null,
    direccion        varchar(200) not null,
    fecha            timestamptz not null default now()
);

create table if not exists reservas (
    id              bigserial primary key,
    usuario_id      bigint not null references usuarios(id) on delete cascade,
    vuelo_id        bigint not null references vuelos(id),
    cantidad_asientos integer not null check (cantidad_asientos > 0),
    total           numeric(10,2) not null,   -- subtotal sin IVA
    estado          varchar(20) not null default 'confirmada'
                    check (estado in ('confirmada','cancelada')),
    fecha_reserva   timestamptz not null default now(),
    compra_id       bigint references compras(id) on delete set null
);

create table if not exists tokens (
    id          bigserial primary key,
    usuario_id  bigint not null references usuarios(id) on delete cascade,
    token       text not null,
    expiracion  timestamptz not null,
    estado      varchar(20) not null default 'activo'
                check (estado in ('activo','revocado'))
);

-- Un registro por asiento de cada vuelo (mapa del avión).
-- estado 'reservado' = comprado. retenido_por/retenido_hasta = retención temporal
-- (alguien lo eligió y aún no paga); caduca sola, sin necesidad de limpiar nada.
create table if not exists asientos_vuelo (
    id             bigserial primary key,
    vuelo_id       bigint not null references vuelos(id) on delete cascade,
    fila           integer not null,
    letra          char(1) not null,
    codigo         varchar(4) not null,
    clase          varchar(12) not null default 'economica'
                   check (clase in ('primera','ejecutiva','economica')),
    estado         varchar(20) not null default 'libre'
                   check (estado in ('libre','reservado')),
    reserva_id     bigint references reservas(id) on delete set null,
    retenido_por   bigint references usuarios(id) on delete set null,
    retenido_hasta timestamptz,
    tipo_pasajero  varchar(10) check (tipo_pasajero in ('adulto','nino')),
    equipaje       varchar(12) check (equipaje in ('mano','bodega23','bodega32')),
    precio_pagado  numeric(10,2),             -- sin IVA, lo que costó este asiento
    unique (vuelo_id, codigo)
);
create index if not exists idx_asientos_vuelo on asientos_vuelo(vuelo_id, fila, letra);
create index if not exists idx_asientos_reserva on asientos_vuelo(reserva_id);

-- Movimientos de dinero: cobros, cobros extra por cambios y reembolsos (monto con IVA)
create table if not exists pagos (
    id          bigserial primary key,
    usuario_id  bigint not null references usuarios(id) on delete cascade,
    compra_id   bigint references compras(id) on delete set null,
    reserva_id  bigint references reservas(id) on delete set null,
    tipo        varchar(20) not null check (tipo in ('cobro','cobro_extra','reembolso')),
    monto       numeric(10,2) not null check (monto >= 0),
    detalle     varchar(200) not null default '',
    fecha       timestamptz not null default now()
);
create index if not exists idx_pagos_reserva on pagos(reserva_id);

create index if not exists idx_reservas_usuario on reservas(usuario_id);
create index if not exists idx_vuelos_busqueda on vuelos(origen, destino, fecha);
create index if not exists idx_tokens_token on tokens(token);

-- Datos de ejemplo (capacidad = total; primera 2 por fila, ejecutiva 4, económica 6)
insert into vuelos (origen, destino, fecha, hora_salida, hora_llegada, precio, capacidad,
                    asientos_disponibles, asientos_primera, asientos_ejecutiva, escalas, ciudades_escala) values
 ('Quito','Guayaquil','2026-12-21','09:45','10:40', 89.00, 40, 40, 4, 8, 0, ''),
 ('Quito','Cuenca','2026-12-21','12:20','14:05', 99.00, 30, 30, 0, 4, 1, 'Guayaquil'),
 ('Quito','Manta','2026-12-21','14:50','15:40', 79.00, 24, 24, 0, 0, 0, ''),
 ('Guayaquil','Quito','2026-12-22','08:00','08:55', 92.00, 36, 36, 2, 8, 0, '');

-- Asientos de los vuelos de ejemplo
do $$
declare v record; i int; fila int; base int; econ int;
begin
  for v in select * from vuelos loop
    base := 0;
    for i in 0 .. v.asientos_primera - 1 loop
      insert into asientos_vuelo (vuelo_id, fila, letra, codigo, clase)
      values (v.id, i / 2 + 1, substr('AF', i % 2 + 1, 1),
              (i / 2 + 1)::text || substr('AF', i % 2 + 1, 1), 'primera')
      on conflict do nothing;
    end loop;
    base := v.asientos_primera / 2;
    for i in 0 .. v.asientos_ejecutiva - 1 loop
      fila := base + i / 4 + 1;
      insert into asientos_vuelo (vuelo_id, fila, letra, codigo, clase)
      values (v.id, fila, substr('ABEF', i % 4 + 1, 1),
              fila::text || substr('ABEF', i % 4 + 1, 1), 'ejecutiva')
      on conflict do nothing;
    end loop;
    base := base + v.asientos_ejecutiva / 4;
    econ := v.capacidad - v.asientos_primera - v.asientos_ejecutiva;
    for i in 0 .. econ - 1 loop
      fila := base + i / 6 + 1;
      insert into asientos_vuelo (vuelo_id, fila, letra, codigo, clase)
      values (v.id, fila, substr('ABCDEF', i % 6 + 1, 1),
              fila::text || substr('ABCDEF', i % 6 + 1, 1), 'economica')
      on conflict do nothing;
    end loop;
  end loop;
end $$;
