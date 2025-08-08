# Guía de formatos abiertos

## Formatos recomendados
- **CSV** (UTF-8, separador coma, encabezado en la primera fila).
- **JSON** y **JSON Lines** para registros.
- **Parquet** para datos tabulares grandes (compresión y tipado).
- **GeoJSON** / **GeoParquet** para datos geoespaciales.

## Buenas prácticas
- Codificación **UTF-8**.
- Fechas ISO 8601 (`YYYY-MM-DD` o timestamp UTC).
- Tipado consistente por columna.
- No mezclar tipos numérico/texto en la misma columna.
