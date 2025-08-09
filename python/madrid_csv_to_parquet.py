#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
madrid_csv_to_parquet.py

- Extrae URLs de un CSV de catálogo (aunque no tenga los enlaces directos).
- Visita las páginas y descubre recursos .csv/.zip.
- Descarga y convierte a Parquet.
- Escribe un inventario con trazabilidad.

Requisitos:
  pip install pandas pyarrow requests tqdm beautifulsoup4 chardet
"""

import argparse
import csv as csv_std
import hashlib
import os
import re
import sys
import zipfile
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List
from urllib.parse import urljoin, urlparse

import chardet
import pandas as pd
import requests
from bs4 import BeautifulSoup
from tqdm import tqdm

# ---------------------------
# Configuración global
# ---------------------------

SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "AytoMadrid-CSV2Parquet-Proposal/1.1 (+contacto-proponente)"
})
TIMEOUT = 60


# ---------------------------
# Modelos y utilidades
# ---------------------------

@dataclass
class ResourceRow:
    source: str            # 'catalog', 'catalog_page' o 'crawl'
    dataset_title: str
    resource_title: str
    url: str
    format: str            # CSV/ZIP/UNKNOWN
    http_status: int = 0
    bytes: int = 0
    sha256: str = ""
    local_path: str = ""
    parquet_path: str = ""
    status: str = "pending"  # pending, downloaded, converted, error
    note: str = ""


def safe_filename(name: str) -> str:
    name = re.sub(r"[^\w\-.]+", "_", name.strip())
    return name[:200] if len(name) > 200 else name


def ensure_dir(p: Path):
    p.mkdir(parents=True, exist_ok=True)


def guess_format_from_url(url: str) -> str:
    url_low = url.lower()
    if url_low.endswith(".csv") or ".csv?" in url_low:
        return "CSV"
    if url_low.endswith(".zip") or ".zip?" in url_low:
        return "ZIP"
    return "UNKNOWN"


def head_status(url: str) -> int:
    try:
        r = SESSION.head(url, allow_redirects=True, timeout=TIMEOUT)
        return r.status_code
    except Exception:
        return 0


def download(url: str, out_path: Path) -> tuple[int, str]:
    """Descarga en streaming y calcula sha256. Devuelve (bytes, sha256)."""
    ensure_dir(out_path.parent)
    h = hashlib.sha256()
    size = 0
    with SESSION.get(url, stream=True, timeout=TIMEOUT) as r:
        r.raise_for_status()
        with open(out_path, "wb") as f:
            for chunk in r.iter_content(chunk_size=1024 * 1024):
                if not chunk:
                    continue
                f.write(chunk)
                h.update(chunk)
                size += len(chunk)
    return size, h.hexdigest()


def detect_encoding(sample: bytes) -> str:
    res = chardet.detect(sample)
    enc = res.get("encoding") or "utf-8"
    return enc.replace("ascii", "utf-8")


def sniff_dialect(sample: bytes):
    text = sample.decode("utf-8", errors="ignore")
    try:
        sniffer = csv_std.Sniffer()
        dialect = sniffer.sniff(text, delimiters=[",", ";", "\t", "|"])
        has_header = sniffer.has_header(text)
        return dialect, has_header
    except Exception:
        class DefaultDialect:
            delimiter = ";"
            quotechar = '"'
            doublequote = True
            escapechar = None
            lineterminator = "\n"
            quoting = csv_std.QUOTE_MINIMAL
        return DefaultDialect(), True


# ---------------------------
# 1) Cargar “catálogo” y extraer TODAS las URLs (no solo .csv/.zip)
# ---------------------------

def load_catalog(catalog_csv: Path) -> List[ResourceRow]:
    """
    Lee el archivo del catálogo como texto (independiente del separador/estructura)
    y extrae por regex TODAS las URLs http/https encontradas. Normalmente serán
    páginas de dataset, no enlaces directos a recursos.
    """
    raw = catalog_csv.read_bytes()
    try:
        enc = chardet.detect(raw).get("encoding") or "utf-8"
    except Exception:
        enc = "utf-8"

    text = raw.decode(enc, errors="replace")

    any_url_pattern = re.compile(r'(https?://[^\s"\'<>]+)', re.IGNORECASE)

    rows: List[ResourceRow] = []
    seen = set()
    for line in text.splitlines():
        urls = any_url_pattern.findall(line)
        if not urls:
            continue
        for u in urls:
            u = u.strip().strip('",;')
            if u in seen:
                continue
            seen.add(u)
            rr = ResourceRow(
                source="catalog",
                dataset_title="",
                resource_title="",
                url=u,
                format=guess_format_from_url(u)  # la mayoría serán UNKNOWN aquí
            )
            rows.append(rr)
    return rows


# ---------------------------
# 2) Visitar páginas del catálogo y extraer .csv / .zip
# ---------------------------

def extract_csv_zip_from_pages(pages: List[ResourceRow], same_host=True, max_per_page=300) -> List[ResourceRow]:
    """
    Visita páginas (normalmente de dataset) y extrae enlaces a .csv/.zip.
    """
    out: List[ResourceRow] = []
    seen_urls = set()

    for rr in tqdm(pages, desc="Explorando páginas del catálogo", unit="page"):
        url = rr.url
        try:
            if same_host:
                p = urlparse(url)
                if p.netloc not in {"datos.madrid.es", "www.madrid.es"}:
                    continue

            resp = SESSION.get(url, timeout=TIMEOUT)
            if not resp.ok or "text/html" not in resp.headers.get("Content-Type", ""):
                continue

            soup = BeautifulSoup(resp.text, "html.parser")

            # Candidatos a recursos
            links = soup.select("a[href]")
            count = 0
            for a in links:
                href = a.get("href", "").strip()
                if not href:
                    continue
                abs_url = urljoin(url, href)
                fmt = guess_format_from_url(abs_url)
                if fmt in ("CSV", "ZIP"):
                    if abs_url in seen_urls:
                        continue
                    seen_urls.add(abs_url)
                    title = (a.text or "").strip()
                    out.append(ResourceRow(
                        source="catalog_page",
                        dataset_title="",
                        resource_title=title,
                        url=abs_url,
                        format=fmt
                    ))
                    count += 1
                    if count >= max_per_page:
                        break

        except Exception:
            # Ignorar errores de una página y continuar
            continue

    # De-duplicar
    dedup = {}
    for r in out:
        dedup[r.url] = r
    return list(dedup.values())


# ---------------------------
# 3) Crawler opcional (desde la portada)
# ---------------------------

def crawl_for_links(start_url: str, max_pages: int = 2000, same_host=True) -> List[ResourceRow]:
    seen = set()
    queue = [start_url]
    out: List[ResourceRow] = []

    parsed_root = urlparse(start_url)
    root_netloc = parsed_root.netloc

    pbar = tqdm(total=max_pages, desc="Crawling", unit="page")
    while queue and len(seen) < max_pages:
        url = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        pbar.update(1)

        try:
            resp = SESSION.get(url, timeout=TIMEOUT)
            if not resp.ok or "text/html" not in resp.headers.get("Content-Type", ""):
                continue
            soup = BeautifulSoup(resp.text, "html.parser")

            # Enlaces a CSV/ZIP
            for a in soup.select("a[href]"):
                href = a.get("href", "").strip()
                abs_url = urljoin(url, href)
                fmt = guess_format_from_url(abs_url)
                if fmt in ("CSV", "ZIP"):
                    title = (a.text or "").strip()
                    out.append(ResourceRow(
                        source="crawl",
                        dataset_title="",
                        resource_title=title,
                        url=abs_url,
                        format=fmt
                    ))

            # Enlaces para seguir
            for a in soup.select("a[href]"):
                href = a.get("href", "").strip()
                abs_url = urljoin(url, href)
                p = urlparse(abs_url)
                if same_host and p.netloc != root_netloc:
                    continue
                if abs_url.startswith(("mailto:", "javascript:")):
                    continue
                if any(abs_url.lower().endswith(ext) for ext in [".csv", ".zip", ".pdf", ".json", ".xml"]):
                    continue
                if abs_url not in seen:
                    queue.append(abs_url)

        except Exception:
            continue

    pbar.close()
    # Eliminar duplicados por URL
    unique = {}
    for r in out:
        unique[r.url] = r
    return list(unique.values())


# ---------------------------
# 4) Conversión CSV -> Parquet
# ---------------------------

def convert_csv_file_to_parquet(csv_path: Path, parquet_path: Path, sample_bytes: int = 256_000):
    ensure_dir(parquet_path.parent)

    # Detectar encoding + delimitador con una muestra
    with open(csv_path, "rb") as f:
        sample = f.read(sample_bytes)
    encoding = detect_encoding(sample)
    dialect, _ = sniff_dialect(sample)

    # Lectura robusta con pandas
    try:
        df = pd.read_csv(
            csv_path,
            encoding=encoding,
            sep=getattr(dialect, "delimiter", ";"),
            quotechar=getattr(dialect, "quotechar", '"'),
            engine="python",  # tolerante
            dtype_backend="pyarrow",
            low_memory=False
        )
    except Exception:
        # Segundo intento con separador común
        df = pd.read_csv(
            csv_path,
            encoding=encoding,
            sep=";",
            engine="python",
            dtype_backend="pyarrow",
            low_memory=False
        )

    # Escribir Parquet
    df.to_parquet(parquet_path, engine="pyarrow", compression="snappy", index=False)


def process_resource(rr: ResourceRow, out_dir: Path, tmp_dir: Path, overwrite=False) -> ResourceRow:
    rr = ResourceRow(**asdict(rr))  # copiar
    try:
        status = head_status(rr.url)
        rr.http_status = status
        if status and status >= 400:
            rr.status = "error"
            rr.note = f"HTTP {status}"
            return rr

        # Nombre base a partir de la URL
        parsed = urlparse(rr.url)
        base = safe_filename(Path(parsed.path).name or "recurso")
        if not base:
            base = "recurso"
        if rr.format == "CSV" and not base.lower().endswith(".csv"):
            base += ".csv"
        local_path = tmp_dir / base

        if not local_path.exists() or overwrite:
            size, sha = download(rr.url, local_path)
            rr.bytes = size
            rr.sha256 = sha
            rr.status = "downloaded"
        else:
            rr.status = "downloaded (cached)"
            rr.bytes = local_path.stat().st_size

        rr.local_path = str(local_path)

        # Convertir
        if rr.format == "CSV":
            parquet_name = safe_filename(base.replace(".csv", "").replace(".CSV", "")) + ".parquet"
            parquet_path = out_dir / parquet_name
            convert_csv_file_to_parquet(local_path, parquet_path)
            rr.parquet_path = str(parquet_path)
            rr.status = "converted"

        elif rr.format == "ZIP":
            # Descomprimir y convertir cada CSV interno
            with zipfile.ZipFile(local_path, "r") as z:
                namelist = z.namelist()
                csv_entries = [n for n in namelist if n.lower().endswith(".csv")]
                if not csv_entries:
                    rr.status = "error"
                    rr.note = "ZIP sin CSV interno"
                    return rr

                for name in csv_entries:
                    with z.open(name) as f:
                        data = f.read()
                    inner_csv = tmp_dir / safe_filename(Path(name).name)
                    with open(inner_csv, "wb") as fout:
                        fout.write(data)
                    parquet_name = safe_filename(Path(name).stem) + ".parquet"
                    parquet_path = out_dir / parquet_name
                    convert_csv_file_to_parquet(inner_csv, parquet_path)

                rr.parquet_path = str(out_dir)
                rr.status = "converted"
        else:
            rr.status = "error"
            rr.note = "Formato no soportado"

        return rr

    except Exception as e:
        rr.status = "error"
        rr.note = str(e)
        return rr


# ---------------------------
# 5) Programa principal
# ---------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Localiza recursos CSV/ZIP en datos.madrid.es (vía catálogo o rastreo), guarda enlaces y convierte a Parquet."
    )
    ap.add_argument("--catalog-file", type=str,
                    help="Ruta a CSV exportado del catálogo (método recomendado).")
    ap.add_argument("--start-url", type=str,
                    help="URL inicial para rastrear (opcional). Ej.: https://datos.madrid.es")
    ap.add_argument("--out-dir", type=str, default="parquet_out",
                    help="Directorio de salida para Parquet.")
    ap.add_argument("--tmp-dir", type=str, default="tmp_downloads",
                    help="Directorio temporal de descargas.")
    ap.add_argument("--max-pages", type=int, default=1500,
                    help="Límite de páginas para el crawler.")
    ap.add_argument("--overwrite", action="store_true",
                    help="Re-descargar y re-convertir aunque existan archivos.")
    ap.add_argument("--inventory-csv", type=str, default="inventory_links.csv",
                    help="Ruta del inventario consolidado (enlaces, estados, rutas locales).")
    args = ap.parse_args()

    out_dir = Path(args.out_dir)
    tmp_dir = Path(args.tmp_dir)
    ensure_dir(out_dir)
    ensure_dir(tmp_dir)

    resources: List[ResourceRow] = []

    # --- Modo catálogo (recomendado)
    if args.catalog_file and Path(args.catalog_file).exists():
        print(f"[INFO] Cargando catálogo: {args.catalog_file}", file=sys.stderr)
        catalog_pages = load_catalog(Path(args.catalog_file))

        # 1) Si el catálogo ya trajese enlaces directos CSV/ZIP, úsalo
        direct = [r for r in catalog_pages if r.format in ("CSV", "ZIP")]
        if direct:
            print(f"[INFO] Encontrados {len(direct)} enlaces directos CSV/ZIP en el catálogo.", file=sys.stderr)
            resources = direct
        else:
            # 2) Si no, visitar las páginas y extraer los enlaces reales
            print("[INFO] No hay enlaces directos a CSV/ZIP en el catálogo. Explorando páginas…", file=sys.stderr)
            page_resources = extract_csv_zip_from_pages(catalog_pages, same_host=True)
            print(f"[INFO] Encontrados {len(page_resources)} enlaces CSV/ZIP tras explorar páginas.", file=sys.stderr)
            resources = page_resources

    # --- Modo crawler (alternativo/extra)
    if args.start_url:
        print(f"[INFO] Rastreo desde: {args.start_url}", file=sys.stderr)
        crawl_rows = crawl_for_links(args.start_url, max_pages=args.max_pages)
        print(f"[INFO] Crawler encontró {len(crawl_rows)} enlaces CSV/ZIP.", file=sys.stderr)
        resources.extend(crawl_rows)

    # De-duplicar por URL
    dedup = {}
    for r in resources:
        dedup[r.url] = r
    resources = list(dedup.values())

    if not resources:
        print("[WARN] No se encontraron recursos CSV/ZIP. Asegúrate de pasar --catalog-file o --start-url.", file=sys.stderr)
        sys.exit(1)

    print(f"[INFO] Recursos a procesar: {len(resources)}", file=sys.stderr)

    results = []
    for rr in tqdm(resources, desc="Procesando recursos", unit="res"):
        res = process_resource(rr, out_dir=out_dir, tmp_dir=tmp_dir, overwrite=args.overwrite)
        results.append(res)

    # Inventario consolidado
    inv_path = Path(args.inventory_csv)
    df_inv = pd.DataFrame([asdict(r) for r in results])
    df_inv.to_csv(inv_path, index=False, encoding="utf-8")
    print(f"[OK] Inventario escrito en: {inv_path}")
    print(f"[OK] Parquet en: {out_dir.resolve()}")


if __name__ == "__main__":
    main()

