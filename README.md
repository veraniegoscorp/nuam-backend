# NUAM backend

Django REST Framework local, con PostgreSQL alojado en Supabase como base de datos. El `.env` se lee desde este directorio y no debe compartirse ni versionarse. Se aceptan las variables `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD` (también los nombres en minúscula del archivo de conexión existente) y `DB_SSLMODE=require`.

## Configuración local

1. Instala dependencias: `python -m pip install -r requirements.txt`.
2. Copia `.env.example` a `.env` y completa localmente las credenciales de Supabase. No publiques los valores.
3. Ejecuta las migraciones del esquema Django: `python manage.py migrate`.
4. Importa de forma aditiva los datos de negocio locales: `python manage.py import_legacy_data`.
5. Crea la primera cuenta con `python manage.py createsuperuser` y asígnale el rol inicial una sola vez: `python manage.py bootstrap_admin --email admin@tu-dominio`.
6. Inicia la API: `python manage.py runserver`.

Si la cuenta inicial fue provisionada sin contraseña, establécela localmente con `python manage.py changepassword <username>`; Django solicitará la nueva contraseña en la terminal.

La importación conserva los datos del destino, no sobrescribe expedientes existentes y se puede repetir. Omite las cuentas de demostración porque usan contraseñas conocidas; los códigos/hash ficticios de documentos sin archivo se descartan. Si el SQLite de origen contiene documentos, el comando se detiene: configura antes Supabase Storage y planifica la migración de objetos. La base actual no contiene archivos.

## Supabase Storage

El Transaction Pooler y las variables `DB_HOST`/`DB_PORT` son solo para PostgreSQL; no habilitan Storage. En el Dashboard, abre **Project Settings > API Keys** para ver la URL del proyecto y una **Secret key** (`sb_secret_...`). Crea un bucket privado llamado `tax-documents` desde **Storage** y configura `SUPABASE_URL` y `SUPABASE_SECRET_KEY` en el `.env` del backend. La clave secreta solo se envía en el encabezado `apikey`; nunca la expongas al navegador ni la compartas.

Las claves antiguas `service_role` también se aceptan mediante `SUPABASE_SERVICE_ROLE_KEY` por compatibilidad. Configura solo una de esas dos variables. En `DEBUG=true`, si no hay URL y clave se usa `MEDIA_ROOT` local para desarrollo. En producción, la aplicación exige PostgreSQL, clave Django y Storage de Supabase.

Los documentos PDF se guardan con un hash SHA-256 calculado en el servidor. Cada descarga vuelve a calcularlo y bloquea la respuesta si no coincide. Los registros antiguos sin archivo no se presentan como verificados ni generan un PDF ficticio.

## Correo 2FA

El primer paso de acceso genera un código aleatorio de seis dígitos, lo envía al correo registrado y guarda únicamente su hash. Vence a los cinco minutos, permite hasta cinco intentos y solo se consume una vez. En local, sin `EMAIL_HOST`, Django imprime el correo en la consola; eso es únicamente para pruebas. Para entrega real configura `EMAIL_HOST`, `EMAIL_PORT`, `EMAIL_HOST_USER`, `EMAIL_HOST_PASSWORD`, `EMAIL_USE_TLS` y `DEFAULT_FROM_EMAIL`. Reinicia el backend después de modificar el `.env` para que cargue los cambios. No confirmes que el correo real funciona hasta probar un envío con el proveedor SMTP.

## Roles y autorización

Todos los endpoints requieren JWT salvo el inicio de sesión. El backend controla los permisos de expedientes, aprobaciones, bitácora y administración de usuarios; el panel React no es una frontera de seguridad. El endpoint `/api/v1/admin/users/` solo admite el rol administrador. Al crear una cuenta, entrega una contraseña temporal de una sola visualización al administrador para que la comparta por un canal seguro; las cuentas nuevas requieren 2FA.

CORS permite solo los orígenes locales indicados en `CORS_ALLOWED_ORIGINS`; no se permiten orígenes globales. La migración revoca permisos de PostgREST (`anon`/`authenticated`) sobre tablas Django y habilita RLS sin políticas públicas; el backend usa su conexión de servidor (con `BYPASSRLS`) y no comparte estas credenciales con el navegador. WhiteNoise sirve estáticos recolectados con `python manage.py collectstatic --noinput`.

## Validación

`python manage.py test tributario` ejecuta pruebas aisladas en SQLite en memoria; no crea ni modifica tablas en Supabase. `python manage.py check` valida configuración local. No ejecutes `seed_data` contra PostgreSQL; el comando está limitado a SQLite.
