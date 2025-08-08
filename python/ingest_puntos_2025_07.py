import duckdb, pandas as pd
CSV = "data/raw/pmed_2025-07.csv"
con = duckdb.connect("data/duckdb/madrid.duckdb")
df = pd.read_csv(CSV)
con.execute("CREATE OR REPLACE TABLE puntos_medida AS SELECT * FROM df")
print(con.execute("SELECT COUNT(*) FROM puntos_medida").fetchone())
