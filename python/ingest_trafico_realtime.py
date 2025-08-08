import duckdb, pandas as pd, requests
from lxml import etree

XML_URL = "https://datos.madrid.es/egob/catalogo/202087-0-trafico-intensidad.xml"
PARQUET_OUT = "data/processed/trafico_realtime.parquet"
DUCKDB_PATH = "data/duckdb/madrid.duckdb"
TABLE = "trafico_realtime"

def parse_xml_to_df(xml_bytes: bytes) -> pd.DataFrame:
    root = etree.fromstring(xml_bytes)
    rows = []
    for pm in root.findall(".//pm"):
        def get(tag):
            v = pm.findtext(tag)
            return v.strip() if v else ""
        def num(v):
            return pd.to_numeric(v, errors="coerce")
        stx = get("st_x").replace(",", ".") if get("st_x") else ""
        sty = get("st_y").replace(",", ".") if get("st_y") else ""
        rows.append({
            "fecha_hora": get("fecha_hora"),
            "idelem": get("idelem"),
            "descripcion": get("descripcion"),
            "accesoAsociado": get("accesoAsociado"),
            "intensidad": num(get("intensidad")),
            "ocupacion": num(get("ocupacion")),
            "carga": num(get("carga")),
            "nivelServicio": num(get("nivelServicio")),
            "intensidadSat": num(get("intensidadSat")),
            "velocidad": num(get("velocidad")),
            "error": get("error"),
            "subarea": get("subarea"),
            "st_x": num(stx),
            "st_y": num(sty),
        })
    df = pd.DataFrame(rows)
    df["fecha_hora"] = pd.to_datetime(df["fecha_hora"], errors="coerce", utc=True)
    df["idelem"] = pd.to_numeric(df["idelem"], errors="coerce", downcast="integer")
    return df

def main():
    r = requests.get(XML_URL, timeout=30)
    r.raise_for_status()
    df = parse_xml_to_df(r.content)
    if df.empty:
        raise SystemExit("El XML no contiene registros 'pm'.")
    df.to_parquet(PARQUET_OUT, index=False)
    con = duckdb.connect(DUCKDB_PATH)
    con.execute(f"CREATE OR REPLACE TABLE {TABLE} AS SELECT * FROM read_parquet('{PARQUET_OUT}')")
    con.execute(f"CREATE INDEX IF NOT EXISTS idx_{TABLE}_fecha ON {TABLE}(fecha_hora)")
    last_ts = df['fecha_hora'].max()
    print(f"Ingestadas {len(df)} filas. Última fecha: {last_ts}")

if __name__ == '__main__':
    main()
