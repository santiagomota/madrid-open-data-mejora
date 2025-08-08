library(pointblank); library(arrow)
df <- arrow::read_parquet("data/processed/trafico_realtime.parquet")

agent <- create_agent(df) |>
  col_vals_not_null(vars(fecha_hora)) |>
  col_vals_between(vars(ocupacion), 0, 100, na_pass = TRUE) |>
  col_vals_between(vars(nivelServicio), 0, 3, na_pass = TRUE) |>
  interrogate()

agent
