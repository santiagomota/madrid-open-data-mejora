library(DBI)
library(duckdb)
library(readr)

con <- dbConnect(duckdb::duckdb(), "data/duckdb/madrid.duckdb")
url <- "https://datos.madrid.es/egob/catalogo/202468-263-intensidad-trafico.csv"
df <- read_csv(url, show_col_types = FALSE)
dbWriteTable(con, "ejemplo_puntos", df, overwrite = TRUE)
print(dbGetQuery(con, "SELECT COUNT(*) AS filas FROM ejemplo_puntos"))
