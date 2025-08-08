library(DBI)
library(duckdb)
library(readr)

# con <- dbConnect(duckdb::duckdb(), "../data/duckdb/madrid.duckdb")

# Podemos usar una base de datos en memoria (limitado por el tamaño de la misma)
# driver_duckdb <- duckdb()

# O podemos hacerla persistente, lo que permite a DuckDB ejecutar procesos con
# mas memoria de la que hay en RAM
driver_duckdb <- duckdb(tempfile(fileext = ".duckdb"))
driver_duckdb

con_duck <- dbConnect(driver_duckdb)
con_duck

# url <- "https://datos.madrid.es/egob/catalogo/202468-263-intensidad-trafico.csv"

# df <- read_csv(url, show_col_types = FALSE)

fecha_objetivo <- data.frame(mes = '07', anio = '2025')

directorio_externo <- "/media/enero/Disco3ATA/Varios/R/Archivos/GIS/data/"

# Incluimos la url (este fichero corresponde a junio 2025)
url <- paste0('https://datos.madrid.es/egobfiles/MANUAL/208627/', 
              fecha_objetivo$mes[1], '-', fecha_objetivo$anio[1], '.zip')

# La url
# url

# Definimos el fichero
# fichero  <- paste0(tempfile(), ".zip")
fichero <- paste0(directorio_externo, 'ayuntamientoMadrid/trafico/historico/', 
                  fecha_objetivo$mes[1], '-', fecha_objetivo$anio[1], '.zip')

# Descargamos el fichero al ordenador (comprimido ocupa 72 Mb)
download.file(url, destfile = fichero)

# Leemos el fichero con la función read.table()
# trafico_mes <- read.table(unzip(fichero, files = "06-2025.csv", exdir = tempdir()), 
#                       header = TRUE, sep = ';', dec = '.')
trafico_mes <- read.table(unzip(fichero, exdir = tempdir()), 
                          header = TRUE, sep = ';', dec = '.')

dbWriteTable(con_duck, "trafico_mes", trafico_mes, overwrite = TRUE)

print(dbGetQuery(con_duck, "SELECT COUNT(*) AS filas FROM trafico_mes"))
