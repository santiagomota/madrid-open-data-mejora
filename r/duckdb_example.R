# r/duckdb_example.R
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
# Si el ZIP contiene múltiples ficheros, cogemos el primero CSV
csv_name <- files_in_zip$Name[grepl("\\.csv$", tolower(files_in_zip$Name))]
if (length(csv_name) == 0) stop("El ZIP no contiene ningún CSV.")
csv_name <- csv_name[1]
csv_path <- unzip(zip_local, files = csv_name, exdir = tmpdir, overwrite = TRUE)

message("CSV detectado en ZIP: ", basename(csv_path))

# ---------------------------
# Lectura del CSV
# - Separador ';'
# - Decimal '.'
# - Codificación: intentamos UTF-8 (ajustable si fuese necesario)
# ---------------------------
# Nota: si el fichero está en ISO-8859-1, usar locale(encoding = "Latin1")
df <- read_delim(
    file   = csv_path,
    delim  = ";",
    locale = locale(decimal_mark = ".", grouping_mark = "", encoding = "UTF-8"),
    show_col_types = FALSE,
    progress = FALSE
)

# Intento opcional de parseo de fecha/hora si existe columna "fecha" o similar
posibles_fechas <- intersect(names(df), c("fecha", "Fecha", "FECHA", "fecha_hora", "datetime"))
if (length(posibles_fechas) > 0) {
    col_f <- posibles_fechas[1]
    # Intento común: "YYYY-MM-DD HH:MM:SS" o similar
    suppressWarnings({
        df[[col_f]] <- parse_datetime(df[[col_f]], locale = locale(tz = "UTC"))
    })
}

# ---------------------------
# Conexión DuckDB y carga
# ---------------------------
con <- dbConnect(duckdb::duckdb(), duckdb_path)

on.exit({
    try(dbDisconnect(con, shutdown = TRUE), silent = TRUE)
})

# Crea/reescribe la tabla
dbWriteTable(con, tabla, df, overwrite = TRUE, temporary = FALSE)

# Índice sobre fecha si existe
if ("fecha" %in% names(df)) {
    try(DBI::dbExecute(con, sprintf("CREATE INDEX IF NOT EXISTS idx_%s_fecha ON %s(fecha)", tabla, tabla)), silent = TRUE)
} else if ("fecha_hora" %in% names(df)) {
    try(DBI::dbExecute(con, sprintf("CREATE INDEX IF NOT EXISTS idx_%s_fecha_hora ON %s(fecha_hora)", tabla, tabla)), silent = TRUE)
}

# Verificación
res <- dbGetQuery(con, sprintf("SELECT COUNT(*) AS filas FROM %s", tabla))
print(res)

message(sprintf("Tabla '%s' creada/actualizada en %s", tabla, duckdb_path))
