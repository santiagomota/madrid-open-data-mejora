# r/duckdb_example.R
# ---------------------------------------------
# Crear la base de datos (opcional, desde terminal):
#   ./duckdb data/duckdb/madrid.duckdb
# ---------------------------------------------

suppressPackageStartupMessages({
    library(DBI)
    library(duckdb)
    library(readr)
    library(fs)
})

# ---------------------------
# Configuración
# ---------------------------
anio <- "2025"
mes  <- "07"   # 01..12
duckdb_path <- "data/duckdb/madrid.duckdb"
cache_dir   <- "data/raw/historico"

# URL del ZIP mensual (formato MM-YYYY.zip)
zip_url <- sprintf("https://datos.madrid.es/egobfiles/MANUAL/208627/%s-%s.zip", mes, anio)

# Rutas locales
dir_create(cache_dir)
zip_local <- file.path(cache_dir, sprintf("%s-%s.zip", mes, anio))

# Nombre de tabla en DuckDB
tabla <- sprintf("trafico_%s_%s", anio, mes)

# ---------------------------
# Descarga con caché
# ---------------------------
if (!file_exists(zip_local)) {
    message("Descargando: ", zip_url)
    download.file(zip_url, destfile = zip_local, mode = "wb", quiet = TRUE)
} else {
    message("Usando ZIP en caché: ", zip_local)
}

# ---------------------------
# Extraer y detectar el CSV
# ---------------------------
tmpdir <- tempdir()
files_in_zip <- unzip(zip_local, list = TRUE)
csv_name <- files_in_zip$Name[grepl("\\.csv$", tolower(files_in_zip$Name))]
if (length(csv_name) == 0) stop("El ZIP no contiene ningún CSV.")
csv_name <- csv_name[1]
csv_path <- unzip(zip_local, files = csv_name, exdir = tmpdir, overwrite = TRUE)
message("CSV detectado en ZIP: ", basename(csv_path))

# ---------------------------
# Conexión DuckDB
# ---------------------------
dir_create(dirname(duckdb_path))
con <- dbConnect(duckdb::duckdb(), duckdb_path)
on.exit({
    try(dbDisconnect(con, shutdown = TRUE), silent = TRUE)
})

# ---------------------------
# Opción A: lectura directa del CSV por DuckDB
# (se evita pasar por data.frame en R)
# ---------------------------
path_escaped <- gsub("'", "''", normalizePath(csv_path, winslash = "/", mustWork = FALSE), fixed = TRUE)

sql_create <- sprintf(
    "CREATE OR REPLACE TABLE %s AS
   SELECT * FROM read_csv_auto('%s', delim=';', header=TRUE, sample_size=-1);",
    tabla, path_escaped
)
DBI::dbExecute(con, sql_create)

# ---------------------------
# Workaround: crear columna temporal 'ts' y ordenar la tabla
# (evita el bug del ART index y acelera consultas por rango con zone maps)
# ---------------------------

# Detectar columna temporal existente
cols_df <- dbGetQuery(con, sprintf("PRAGMA table_info(%s);", tabla))
cols <- cols_df$name
time_col <- if ("fecha_hora" %in% cols) "fecha_hora" else if ("fecha" %in% cols) "fecha" else NA_character_
if (is.na(time_col)) stop("No se encontró columna temporal ('fecha_hora' o 'fecha').")

# Renombrar tabla actual a *_old
DBI::dbExecute(con, sprintf("ALTER TABLE %s RENAME TO %s_old;", tabla, tabla))

# Recrear tipando 'ts' con varios formatos comunes
sql_with_ts <- sprintf("
CREATE OR REPLACE TABLE %1$s AS
SELECT
  t.*,
  COALESCE(
    try_strptime(CAST(t.%2$s AS VARCHAR), '%%Y-%%m-%%d %%H:%%M:%%S'),
    try_strptime(CAST(t.%2$s AS VARCHAR), '%%d/%%m/%%Y %%H:%%M:%%S'),
    try_strptime(CAST(t.%2$s AS VARCHAR), '%%Y/%%m/%%d %%H:%%M:%%S'),
    try_strptime(CAST(t.%2$s AS VARCHAR), '%%Y-%%m-%%dT%%H:%%M:%%S'),
    try_strptime(CAST(t.%2$s AS VARCHAR), '%%d/%%m/%%Y')
  ) AS ts
FROM %1$s_old t;
", tabla, time_col)
DBI::dbExecute(con, sql_with_ts)

# Ordenar físicamente por 'ts' para potenciar zone maps
DBI::dbExecute(con, sprintf("
  CREATE OR REPLACE TABLE %1$s AS
  SELECT * FROM %1$s ORDER BY ts NULLS LAST;
", tabla))

# Limpieza: eliminar tabla antigua y checkpoint
DBI::dbExecute(con, sprintf("DROP TABLE IF EXISTS %s_old;", tabla))
DBI::dbExecute(con, "CHECKPOINT;")

# ---------------------------
# Verificación
# ---------------------------
res <- dbGetQuery(con, sprintf("SELECT COUNT(*) AS filas, min(ts) AS ts_min, max(ts) AS ts_max FROM %s;", tabla))
print(res)

message(sprintf("Tabla '%s' creada/actualizada y ordenada por ts en %s", tabla, duckdb_path))

dbDisconnect(con)