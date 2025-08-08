suppressPackageStartupMessages({
  library(DBI)
  library(duckdb)
  library(dplyr)
  library(leaflet)
})

duckdb_path <- "data/duckdb/madrid.duckdb"
con <- DBI::dbConnect(duckdb::duckdb(), duckdb_path)
on.exit({ try(DBI::dbDisconnect(con, shutdown = TRUE), silent = TRUE) })

src_name <- if ("v_trafico_enriquecido" %in% DBI::dbListTables(con)) "v_trafico_enriquecido" else "trafico_2025_07"
fields <- DBI::dbListFields(con, src_name)

pos_x <- intersect(fields, c("st_x", "lon", "long", "longitude"))
pos_y <- intersect(fields, c("st_y", "lat", "latitude"))
stopifnot(length(pos_x) >= 1, length(pos_y) >= 1)

time_col <- intersect(fields, c("ts", "fecha_hora"))[1]

df_map <- tbl(con, dplyr::sql(sprintf("
  SELECT %s AS t, idelem, %s AS lon, %s AS lat,
         intensidad, ocupacion, coalesce(descripcion, '') AS descripcion
  FROM %s
  WHERE %s >= now() - INTERVAL 30 MINUTE
  AND %s IS NOT NULL AND %s IS NOT NULL
  LIMIT 1000
", time_col, pos_x[1], pos_y[1], src_name, time_col, pos_x[1], pos_y[1]))) %>% collect()

leaflet(df_map) |>
  addTiles() |>
  addCircleMarkers(~lon, ~lat,
                   radius = ~pmax(3, pmin(10, intensidad/100)),
                   popup = ~paste0("<b>idelem:</b> ", idelem,
                                   "<br><b>hora:</b> ", t,
                                   "<br><b>intensidad:</b> ", intensidad,
                                   "<br><b>ocupación:</b> ", ocupacion,
                                   "<br><b>punto:</b> ", descripcion))
