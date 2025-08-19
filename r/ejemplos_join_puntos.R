suppressPackageStartupMessages({
  library(DBI)
  library(duckdb)
  library(dplyr)
})

duckdb_path <- "data/duckdb/madrid.duckdb"
con <- DBI::dbConnect(duckdb::duckdb(), duckdb_path)
on.exit({ try(DBI::dbDisconnect(con, shutdown = TRUE), silent = TRUE) })

stopifnot("puntos_medida" %in% DBI::dbListTables(con))

src_name <- if ("v_trafico_enriquecido" %in% DBI::dbListTables(con)) "v_trafico_enriquecido" else "trafico_2025_07"
time_col <- intersect(DBI::dbListFields(con, src_name), c("ts", "fecha_hora"))[1]

traf <- tbl(con, src_name)
pmed <- tbl(con, "puntos_medida")

cols_pmed <- DBI::dbListFields(con, "puntos_medida")
stopifnot(all(c("id") %in% cols_pmed))
stopifnot("idelem" %in% DBI::dbListFields(con, src_name))

enriq <- traf %>%
  filter(!!sym(time_col) >= dplyr::sql("now() - INTERVAL 90 MINUTE")) %>%
  left_join(pmed %>% select(id, descripcion, distrito, barrio), by = c("idelem" = "id")) %>%
  select(!!sym(time_col), idelem, descripcion, distrito, barrio, intensidad, ocupacion, nivelServicio) %>%
  arrange(desc(!!sym(time_col))) %>%
  head(100) %>%
  collect()

print(enriq, n = 20)

dbDisconnect(con)
