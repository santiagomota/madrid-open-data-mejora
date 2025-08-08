# Proyecto de mejora del Portal de Datos Abiertos del Ayuntamiento de Madrid

[![CI](https://github.com/santiagomota/madrid-open-data-mejora/actions/workflows/validate.yml/badge.svg)](https://github.com/santiagomota/madrid-open-data-mejora/actions/workflows/validate.yml)

**Autor:** Santiago Mota

Este repositorio forma parte de la propuesta para la categoría **"Mejora de la calidad del portal"** de los Premios a la Reutilización de Datos Abiertos (2025).

El objetivo es demostrar, mediante ejemplos prácticos, cómo implementar mejoras concretas en:
1. Ejemplos de uso en **R** y **Python**.
2. Integración directa con **DuckDB**.
3. Uso de **formatos abiertos** (CSV, JSON, Parquet, GeoParquet).
4. **Validación automática** de datasets.
5. Herramientas para facilitar el uso (Makefile y vistas SQL).

## Estructura del repositorio

```
data/           # Datos originales y procesados
r/              # Scripts y ejemplos en R
python/         # Scripts y ejemplos en Python
validation/     # Esquemas y validaciones automáticas
cli/            # (Reservado) Herramienta de línea de comandos
docs/           # Guías y documentación
sql/            # Vistas y consultas SQL para DuckDB
```

## Requisitos

- **R** (≥ 4.0) + paquetes `duckdb`, `DBI`, `readr`, `pointblank`.
- **Python** (≥ 3.9) + paquetes `duckdb`, `pandas`, `lxml`, `great_expectations`, `pyarrow`.
- **DuckDB** (≥ 0.9).
- `make` (opcional, para automatizar tareas).
- Conexión a Internet para descargar los datos del portal.

## Uso rápido

```bash
# 1. Clonar el repositorio
git clone https://github.com/USUARIO/madrid-open-data-mejora.git
cd madrid-open-data-mejora

# 2. Crear entorno (opcional)
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 3. Demostración completa
make demo-realtime

# 4. Validación (opcional)
make validate-realtime
```

### Referencias de los datasets utilizados
- **Tráfico en tiempo real (XML):** https://datos.madrid.es/egob/catalogo/202087-0-trafico-intensidad.xml
- **Puntos de medida (CSV, 2025-07):** https://datos.madrid.es/egob/catalogo/202468-263-intensidad-trafico.csv


## Integración continua (CI)

Este repositorio incluye un flujo de trabajo de GitHub Actions (`.github/workflows/validate.yml`) que ejecuta:

1. Instalación de dependencias de Python y R.
2. Descarga del CSV de puntos de medida (2025-07).
3. Ingesta del XML de tráfico en tiempo real y creación de vistas en DuckDB.
4. Validaciones automáticas en R y Python.

El estado de la CI se muestra en la insignia de la cabecera. Si tu *fork* tiene un nombre o usuario distinto, actualiza el enlace de la insignia en el `README.md`.
