#!/bin/sh
# Runs once, on a fresh data directory only (the postgres image skips /docker-entrypoint-initdb.d
# when the database already exists), as the owner role, after 01-schema.sql.
#  - creates a runtime role with data access only (no DDL, not superuser)
#  - replaces the stock guacadmin/guacadmin credential before the database accepts connections
set -eu
APP_PW="$(cat /run/secrets/guac_db_password)"
ADMIN_PW="$(cat /run/secrets/guac_admin_password)"
# Guacamole's scheme: SHA-256 of the password followed by the salt as uppercase hex.
SALT="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' | tr 'a-f' 'A-F')"
HASH="$(printf '%s%s' "$ADMIN_PW" "$SALT" | sha256sum | cut -d' ' -f1)"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<SQL
CREATE ROLE guacamole_app LOGIN PASSWORD '${APP_PW}' NOSUPERUSER NOCREATEDB NOCREATEROLE;
GRANT CONNECT ON DATABASE ${POSTGRES_DB} TO guacamole_app;
GRANT USAGE ON SCHEMA public TO guacamole_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO guacamole_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO guacamole_app;
UPDATE guacamole_user
   SET password_hash = decode('${HASH}', 'hex'), password_salt = decode('${SALT}', 'hex'), password_date = now()
 WHERE entity_id = (SELECT entity_id FROM guacamole_entity WHERE name = 'guacadmin' AND type = 'USER');
SQL
