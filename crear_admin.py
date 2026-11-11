"""
Crea (o promueve) un usuario administrador.

Uso (en la carpeta de la API, con el .env configurado):

  Crear un administrador nuevo:
      python crear_admin.py "Nombre Apellido" correo@mail.com contraseña

  Convertir en administrador a un usuario que ya registraste desde la app:
      python crear_admin.py correo@mail.com
"""
import os
import sys

import psycopg2
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash

load_dotenv()


def main():
    if len(sys.argv) == 2:                       # solo el correo: promover
        nombre, correo, password = None, sys.argv[1].lower().strip(), None
    elif len(sys.argv) == 4:                     # nombre, correo, contraseña: crear
        nombre, correo, password = sys.argv[1], sys.argv[2].lower().strip(), sys.argv[3]
    else:
        print(__doc__)
        sys.exit(1)

    conn = psycopg2.connect(os.environ["DATABASE_URL"])
    with conn, conn.cursor() as cur:
        cur.execute("select id from usuarios where correo = %s", (correo,))
        existe = cur.fetchone()
        if existe:
            cur.execute("update usuarios set rol = 'administrador' where correo = %s", (correo,))
            print(f"{correo} ahora es administrador (su contraseña no se modificó).")
        elif password is None:
            print(f"No existe ningún usuario con el correo {correo}. "
                  "Para crearlo usa: python crear_admin.py \"Nombre\" correo contraseña")
            sys.exit(1)
        else:
            if len(password) < 6:
                print("La contraseña debe tener al menos 6 caracteres")
                sys.exit(1)
            cur.execute(
                "insert into usuarios (nombre, correo, password_hash, rol) "
                "values (%s, %s, %s, 'administrador')",
                (nombre, correo, generate_password_hash(password)),
            )
            print(f"Administrador creado: {correo}")
    conn.close()


if __name__ == "__main__":
    main()