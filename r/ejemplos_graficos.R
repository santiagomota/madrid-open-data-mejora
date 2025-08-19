suppressPackageStartupMessages({
  library(DBI)
  library(duckdb)
  library(dplyr)
  library(ggplot2)
})

duckdb_path <- "data/duckdb/madrid.duckdb"
con <- DBI::dbConnect(duckdb::duckdb(), duckdb_path)
on.exit({ try(DBI::dbDisconnect(con, shutdown = TRUE), silent = TRUE) })

src_name <- if ("v_trafico_enriquecido" %in% DBI::dbListTables(con)) "v_trafico_enriquecido" else "trafico_2025_07"
time_col <- intersect(DBI::dbListFields(con, src_name), c("ts", "fecha_hora"))[1]

serie <- tbl(con, dplyr::sql(sprintf("
  SELECT date_trunc('minute', %s) AS minuto,
         avg(intensidad) AS intensidad_media
  FROM %s
  WHERE %s >= now() - INTERVAL 2 HOUR
  GROUP BY 1
  ORDER BY 1
", time_col, src_name, time_col))) %>% collect()

ggplot(serie, aes(x = minuto, y = intensidad_media)) +
  geom_line() +
  labs(title = "Intensidad media por minuto (últimas 2 horas)",
       x = "Minuto", y = "Intensidad media")

topn <- tbl(con, dplyr::sql(sprintf("
  SELECT idelem, avg(intensidad) AS imedia
  FROM %s
  WHERE %s >= now() - INTERVAL 1 HOUR
  GROUP BY idelem
  ORDER BY imedia DESC
  LIMIT 15
", src_name, time_col))) %>% collect()

ggplot(topn, aes(x = reorder(as.factor(idelem), imedia), y = imedia)) +
  geom_col() +
  coord_flip() +
  labs(title = "Top 15 puntos por intensidad media (última hora)",
       x = "idelem", y = "Intensidad media")

dbDisconnect(con)