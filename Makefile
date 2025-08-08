DATA_DIR = data/raw
PROCESSED = data/processed
DUCK = data/duckdb/madrid.duckdb

# 1. Descarga puntos de medida julio 2025
fetch-puntos-2025-07:
	mkdir -p $(DATA_DIR)
	curl -L "https://datos.madrid.es/egob/catalogo/202468-263-intensidad-trafico.csv" \
		-o "$(DATA_DIR)/pmed_2025-07.csv"

# 2. Ingresa tráfico en tiempo real
ingest-realtime:
	python python/ingest_trafico_realtime.py

# 3. Ingresa puntos de medida a DuckDB
ingest-puntos-2025-07:
	duckdb $(DUCK) -c "CREATE OR REPLACE TABLE puntos_medida AS SELECT * FROM read_csv_auto('$(DATA_DIR)/pmed_2025-07.csv', SAMPLE_SIZE=-1);"

# 4. Crea vistas
views:
	duckdb $(DUCK) -c ".read sql/trafico_views.sql"

# 5. Valida tráfico en tiempo real
validate-realtime:
	Rscript r/validate_trafico.R && python python/validate_trafico.py

# 6. Demo completa: descarga + ingesta + vistas + consulta ejemplo
demo-realtime: fetch-puntos-2025-07 ingest-realtime ingest-puntos-2025-07 views
	@echo "Consulta de ejemplo sobre v_trafico_enriquecido:"
	duckdb $(DUCK) -c "SELECT fecha_hora, idelem, desc_punto, intensidad, ocupacion, nivelServicio FROM v_trafico_enriquecido LIMIT 20;"
