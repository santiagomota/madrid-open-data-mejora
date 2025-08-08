suppressPackageStartupMessages({
  library(DBI)
  library(duckdb)
  library(dplyr)
  library(dbplyr)
})

duckdb_path <- "data/duckdb/madrid.duckdb"
con <- DBI::dbConnect(duckdb::duckdb(), duckdb_path)
on.exit({ try(DBI::dbDisconnect(con, shutdown = TRUE), silent = TRUE) })

src_name <- if ("v_trafico_enriquecido" %in% DBI::dbListTables(con)) "v_trafico_enriquecido" else "trafico_2025_07"

tr <- dplyr::tbl(con, src_name)

time_col <- intersect(colnames(tr), c("ts", "fecha_hora"))[1]
stopifnot(length(time_col) == 1)

ultimos_30min <- tr %>%
  filter(!!sym(time_col) >= dplyr::sql("now() - INTERVAL 30 MINUTE")) %>%
  select(!!sym(time_col), idelem, intensidad, ocupacion, nivelServicio) %>%
  arrange(desc(!!sym(time_col))) %>%
  head(50) %>%
  collect()

print(ultimos_30min)

tcol_sql <- if (time_col == "ts") "ts" else "fecha_hora"
resumen <- dplyr::tbl(con, dplyr::sql(sprintf("
  SELECT date_trunc('minute', %s) AS minuto,
         subarea,
         avg(intensidad) AS intensidad_media,
         avg(ocupacion)  AS ocupacion_media
  FROM %s
  WHERE %s >= now() - INTERVAL 2 HOUR
  GROUP BY 1,2
  ORDER BY 1 DESC
", tcol_sql, src_name, tcol_sql))) %>% collect()

print(resumen, n = 10)

top10 <- dplyr::tbl(con, dplyr::sql(sprintf("
  SELECT idelem, %s AS t, avg(intensidad) AS intensidad_media
  FROM %s
  WHERE %s >= now() - INTERVAL 1 HOUR
  GROUP BY idelem, t
  ORDER BY intensidad_media DESC
  LIMIT 10
", tcol_sql, src_name, tcol_sql))) %>% collect()

print(top10)
