# API y datasets utilizados

- **Tráfico en tiempo real (XML):** https://datos.madrid.es/egob/catalogo/202087-0-trafico-intensidad.xml
- **Puntos de medida (CSV, 2025-07):** https://datos.madrid.es/egob/catalogo/202468-263-intensidad-trafico.csv

La ingesta procesa el XML a Parquet y lo carga en DuckDB. Los puntos de medida se cargan desde el CSV mensual y se enlazan por la clave del elemento (`idelem` en tráfico, `id` en puntos). Ajuste el nombre de columna si fuese necesario.
