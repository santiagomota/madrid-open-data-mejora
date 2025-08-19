suppressPackageStartupMessages({
  library(DBI)
  library(duckdb)
  library(dplyr)
  library(dbplyr)    
  library(arrow)
})

duckdb_path <- "data/duckdb/madrid.duckdb"
con <- DBI::dbConnect(duckdb::duckdb(), duckdb_path)
on.exit({ try(DBI::dbDisconnect(con, shutdown = TRUE), silent = TRUE) })

src_name <- if ("v_trafico_enriquecido" %in% DBI::dbListTables(con)) "v_trafico_enriquecido" else "trafico_2025_07"
time_col <- intersect(DBI::dbListFields(con, src_name), c("ts", "fecha_hora"))[1]

out_dir <- "data/processed"
dir.create(out_dir, showWarnings = FALSE, recursive = TRUE)

# resumen <- dplyr::tbl(con, dplyr::sql(sprintf("
#   SELECT date_trunc('minute', %s) AS minuto,
#          subarea,
#          avg(intensidad) AS intensidad_media,
#          avg(ocupacion)  AS ocupacion_media
#   FROM %s
#   WHERE %s >= now() - INTERVAL 60 MINUTE
#   GROUP BY 1,2
#   ORDER BY 1 DESC
# ", time_col, src_name, time_col))) %>% collect()

resumen_query <- tbl(con, src_name) %>%
    group_by(fecha, id) %>%
    summarise(
        intensidad_media = mean(intensidad, na.rm = TRUE),
        ocupacion_media  = mean(ocupacion, na.rm = TRUE),
        .groups = "drop"
    ) %>%
    arrange(desc(fecha))

# Mostrar la SQL generada
show_query(resumen_query)

# Ejecutar y traer resultados
resumen <- collect(resumen_query)
print(resumen)



arrow::write_parquet(resumen, file.path(out_dir, "resumen_diario.parquet"))
write.csv(resumen, file.path(out_dir, "resumen_diario.csv"), row.names = FALSE)
