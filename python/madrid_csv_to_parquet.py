#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
madrid_csv_to_parquet.py

- Descubre recursos .csv/.zip (vía catálogo, rastreo desde portada o directamente desde --tmp-dir).
- Convierte a Parquet de forma robusta (streaming para ficheros grandes).
- Inventario de resultados con trazabilidad.
- Logs a consola y (opcionalmente) a fichero (--log-file).
- Modo efímero (--ephemeral): usar tmp-dir y borrar descargas tras convertir (opcional).
- --skip-download: salta la descarga y convierte usando ficheros ya presentes en --tmp-dir.
- NUEVO: --from-tmp: procesa recursivamente todos los .csv/.zip encontrados en --tmp-dir.

Casos de uso:
1) Flujo completo (descargar + convertir)
2) Solo convertir lo ya descargado en tmp-dir: --skip-download
3) Efímero (descarga, convierte y borra originales): --ephemeral
4) Procesar lo que haya en tmp-dir sin red: --from-tmp (opcionalmente junto a otros modos)

Requisitos:
  pip install --upgrade pandas pyarrow fastparquet requests tqdm beautifulsoup4 chardet
"""

import argparse
import csv as csv_std
import hashlib
import sys
import zipfile
import re
import logging
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
    "User-Agent": "AytoMadrid-CSV2Parquet-Proposal/1.6 (+contacto-proponente)"
})
TIMEOUT = 60
VERBOSE = False
EPHEMERAL = False         # Si True, borra originales tras convertir (cuando hay descarga)
SKIP_DOWNLOAD = False     # Si True, no descarga: busca ficheros en tmp-dir y convierte
log = logging.getLogger(__name__)  # se configura en main()


# ---------------------------
# Modelos y utilidades
# ---------------------------

@dataclass
class ResourceRow:
    source: str            # 'catalog', 'catalog_page', 'crawl' o 'local'
    dataset_title: str
    resource_title: str
    url: str               # http(s) o ruta local si source='local'
    format: str            # CSV/ZIP/UNKNOWN
    http_status: int = 0
    bytes: int = 0
    sha256: str = ""
    local_path: str = ""   # Ruta local si ya existe el archivo
    parquet_path: str = ""
    status: str = "pending"  # pending, downloaded, converted, error, missing_local
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
    log.info(f"[CAT] URLs detectadas en catálogo: {len(rows)} (únicas: {len(seen)})")
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

            if VERBOSE:
                log.debug(f"[PAGE] {url} -> {count} recursos CSV/ZIP")

        except Exception as e:
            log.debug(f"[PAGE-ERR] {url}: {e}")
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

        except Exception as e:
            log.debug(f"[CRAWL-ERR] {url}: {e}")
            continue

    pbar.close()
    # Eliminar duplicados por URL
    unique = {}
    for r in out:
        unique[r.url] = r
    log.info(f"[CRAWL] Enlaces CSV/ZIP encontrados: {len(unique)}")
    return list(unique.values())


# ---------------------------
# 4) Conversión CSV -> Parquet (robusta, con streaming)
# ---------------------------

def convert_csv_file_to_parquet(csv_path: Path, parquet_path: Path, sample_bytes: int = 512_000, verbose: bool = False):
    """
    Conversión robusta:
    - Detecta codificación (incluye UTF-16).
    - Sniffer de delimitador y fallback.
    - on_bad_lines='skip' para filas corruptas.
    - Modo "streaming" con chunks si el archivo es grande (> ~200MB).
    - Fallback a fastparquet si no hay pyarrow.
    """
    ensure_dir(parquet_path.parent)

    # Detectar codificación + delimitador con una muestra
    with open(csv_path, "rb") as f:
        sample = f.read(sample_bytes)
    encoding = detect_encoding(sample)
    if "UTF-16" in encoding.upper():
        encoding = "utf-16"
    dialect, _ = sniff_dialect(sample)

    # Elegir motor parquet
    parquet_engine = None
    try:
        import pyarrow  # noqa: F401
        parquet_engine = "pyarrow"
    except Exception:
        try:
            import fastparquet  # noqa: F401
            parquet_engine = "fastparquet"
        except Exception:
            raise RuntimeError("No se encontró ni 'pyarrow' ni 'fastparquet'. Instale uno: pip install pyarrow")

    # Heurística de tamaño para decidir streaming
    file_size = csv_path.stat().st_size
    streaming = file_size > 200 * 1024 * 1024  # >200MB

    if verbose:
        log.debug(f"[CONVERT] {csv_path.name} -> {parquet_path.name} | enc={encoding} sep={getattr(dialect,'delimiter',';')} size={file_size/1e6:.1f}MB engine={parquet_engine} streaming={streaming}")

    # Parámetros comunes de lectura
    read_kwargs = dict(
        encoding=encoding,
        sep=getattr(dialect, "delimiter", ";"),
        quotechar=getattr(dialect, "quotechar", '"'),
        engine="python",
        low_memory=False,
        on_bad_lines="skip"
    )

    # Fallbacks si falla la lectura directa
    def read_full():
        try:
            return pd.read_csv(csv_path, **read_kwargs)
        except Exception:
            for enc_try in [encoding, "latin1", "utf-8", "utf-16"]:
                for sep_try in [read_kwargs["sep"], ";", ",", "\t", "|"]:
                    try:
                        return pd.read_csv(
                            csv_path,
                            encoding=enc_try,
                            sep=sep_try,
                            engine="python",
                            low_memory=False,
                            on_bad_lines="skip"
                        )
                    except Exception:
                        continue
            raise

    def read_stream_and_write():
        if parquet_engine == "pyarrow":
            import pyarrow as pa
            import pyarrow.parquet as pq
            writer = None
            try:
                for chunk in pd.read_csv(csv_path, chunksize=200_000, **read_kwargs):
                    table = pa.Table.from_pandas(chunk, preserve_index=False)
                    if writer is None:
                        writer = pq.ParquetWriter(parquet_path, table.schema, compression="snappy")
                    writer.write_table(table)
                if writer:
                    writer.close()
            finally:
                if writer:
                    try:
                        writer.close()
                    except Exception:
                        pass
        else:
            first = True
            for chunk in pd.read_csv(csv_path, chunksize=200_000, **read_kwargs):
                if first:
                    chunk.to_parquet(parquet_path, engine="fastparquet", compression="snappy", index=False)
                    first = False
                else:
                    chunk.to_parquet(parquet_path, engine="fastparquet", compression="snappy", index=False, append=True)

    if not streaming:
        df = read_full()
        try:
            df.to_parquet(parquet_path, engine=parquet_engine, compression="snappy", index=False)
        except Exception as e:
            if verbose:
                log.debug(f"[WARN] to_parquet directo falló: {e}. Reintentando streaming…")
            read_stream_and_write()
    else:
        read_stream_and_write()


# ---------------------------
# 5) Descubrir recursos locales en tmp-dir (NUEVO)
# ---------------------------

def discover_local_resources(tmp_dir: Path) -> List[ResourceRow]:
    """
    Busca recursivamente .csv y .zip en tmp_dir y devuelve ResourceRow listos para convertir.
    """
    rows: List[ResourceRow] = []
    for ext in ("*.csv", "*.CSV", "*.zip", "*.ZIP"):
        for p in tmp_dir.rglob(ext):
            fmt = "CSV" if p.suffix.lower() == ".csv" else "ZIP"
            try:
                size = p.stat().st_size
            except Exception:
                size = 0
            rows.append(ResourceRow(
                source="local",
                dataset_title="",
                resource_title=str(p.relative_to(tmp_dir)),
                url=str(p),                # usamos la ruta local en url
                format=fmt,
                http_status=0,
                bytes=size,
                sha256="",
                local_path=str(p),
                parquet_path="",
                status="pending",
                note=""
            ))
    log.info(f"[LOCAL] Archivos locales detectados en tmp-dir: {len(rows)}")
    return rows


# ---------------------------
# 6) Proceso de cada recurso
# ---------------------------

def process_resource(rr: ResourceRow, out_dir: Path, tmp_dir: Path, overwrite=False) -> ResourceRow:
    """
    Lógica de conversión:
    - Si rr.source='local' o rr.local_path existe: usa ese fichero (sin red).
    - Si SKIP_DOWNLOAD=True: NO descarga; usa el fichero en tmp_dir derivado de la URL (si no existe -> missing_local).
    - Si SKIP_DOWNLOAD=False: descarga a tmp_dir si no existe o si --overwrite.
    - Si EPHEMERAL=True y hubo descarga: borra originales tras convertir.
    """
    rr = ResourceRow(**asdict(rr))  # copia defensiva
    try:
        # Determinar si es local ya disponible
        local_mode = False
        if rr.local_path:
            lp = Path(rr.local_path)
            if lp.exists():
                local_path = lp
                local_mode = True
            else:
                # limpiar si la ruta guardada no existe
                rr.local_path = ""
                local_mode = False

        # Si no es local explícito, derivar nombre a partir de la URL en tmp-dir
        if not local_mode:
            parsed = urlparse(rr.url)
            # si no es http/https (p.ej. ruta local en url), tratarla como local
            if parsed.scheme not in ("http", "https") and Path(rr.url).exists():
                local_path = Path(rr.url)
                local_mode = True
            else:
                base = safe_filename(Path(parsed.path).name or "recurso")
                if rr.format == "CSV" and not base.lower().endswith(".csv"):
                    base += ".csv"
                local_path = tmp_dir / base

        # Gestión según flags
        if local_mode or SKIP_DOWNLOAD:
            # No tocar red. Verificar existencia
            if not local_path.exists():
                rr.status = "missing_local"
                rr.note = "skip-download/local: archivo no encontrado en tmp-dir"
                rr.local_path = ""
                rr.http_status = 0
                return rr
            rr.status = "downloaded (existing)"
            rr.bytes = local_path.stat().st_size
            rr.local_path = str(local_path)
            rr.http_status = 0
        else:
            # Descarga normal
            status = head_status(rr.url)
            rr.http_status = status
            if status and status >= 400:
                rr.status = "error"
                rr.note = f"HTTP {status}"
                return rr

            need_download = (not local_path.exists()) or overwrite
            if need_download:
                if VERBOSE:
                    log.debug(f"[DL] {rr.url}")
                size, sha = download(rr.url, local_path)
                rr.bytes = size
                rr.sha256 = sha
                rr.status = "downloaded"
            else:
                rr.status = "downloaded (cached)"
                rr.bytes = local_path.stat().st_size

            rr.local_path = str(local_path)

        def _cleanup_file(p: Path):
            try:
                if p.exists():
                    p.unlink()
            except Exception:
                pass

        # Conversión
        if rr.format == "CSV":
            parquet_name = safe_filename(Path(rr.local_path).stem) + ".parquet"
            parquet_path = out_dir / parquet_name
            try:
                convert_csv_file_to_parquet(Path(rr.local_path), parquet_path, verbose=VERBOSE)
                rr.parquet_path = str(parquet_path)
                rr.status = "converted"
            except Exception as e:
                rr.status = "error"
                rr.note = f"convert_csv failed: {e}"
            finally:
                if EPHEMERAL and (not SKIP_DOWNLOAD) and (not local_mode):
                    _cleanup_file(Path(rr.local_path))
                    rr.local_path = ""
                    if rr.status == "converted":
                        rr.note = (rr.note + " | ephemeral: source deleted").strip(" |")

        elif rr.format == "ZIP":
            try:
                with zipfile.ZipFile(rr.local_path, "r") as z:
                    namelist = z.namelist()
                    csv_entries = [n for n in namelist if n.lower().endswith(".csv")]
                    if not csv_entries:
                        rr.status = "error"
                        rr.note = "ZIP sin CSV interno"
                        if EPHEMERAL and (not SKIP_DOWNLOAD) and (not local_mode):
                            _cleanup_file(Path(rr.local_path))
                            rr.local_path = ""
                        return rr

                    for name in csv_entries:
                        with z.open(name) as f:
                            data = f.read()
                        inner_csv = Path(tmp_dir) / safe_filename(Path(name).name)
                        with open(inner_csv, "wb") as fout:
                            fout.write(data)
                        parquet_name = safe_filename(Path(name).stem) + ".parquet"
                        parquet_path = Path(out_dir) / parquet_name
                        try:
                            convert_csv_file_to_parquet(inner_csv, parquet_path, verbose=VERBOSE)
                        finally:
                            if EPHEMERAL and (not SKIP_DOWNLOAD) and (not local_mode):
                                _cleanup_file(inner_csv)

                    rr.parquet_path = str(out_dir)
                    rr.status = "converted"
            except Exception as e:
                rr.status = "error"
                rr.note = f"zip/convert failed: {e}"
            finally:
                if EPHEMERAL and (not SKIP_DOWNLOAD) and (not local_mode):
                    _cleanup_file(Path(rr.local_path))
                    rr.local_path = ""
                    if rr.status == "converted":
                        rr.note = (rr.note + " | ephemeral: source deleted").strip(" |")
        else:
            rr.status = "error"
            rr.note = f"Formato no soportado: {rr.format}"

        return rr

    except Exception as e:
        rr.status = "error"
        rr.note = str(e)
        return rr


# ---------------------------
# 7) Programa principal
# ---------------------------

def main():
    global VERBOSE, EPHEMERAL, SKIP_DOWNLOAD, log

    ap = argparse.ArgumentParser(
        description="Localiza recursos CSV/ZIP en datos.madrid.es (catálogo, rastreo o local), guarda enlaces y convierte a Parquet."
    )
    ap.add_argument("--catalog-file", type=str,
                    help="Ruta a CSV exportado del catálogo (método recomendado).")
    ap.add_argument("--start-url", type=str,
                    help="URL inicial para rastrear (opcional). Ej.: https://datos.madrid.es")
    ap.add_argument("--from-tmp", action="store_true",
                    help="Procesar recursivamente todos los .csv/.zip en --tmp-dir (sin red).")
    ap.add_argument("--out-dir", type=str, default="parquet_out",
                    help="Directorio de salida para Parquet.")
    ap.add_argument("--tmp-dir", type=str, default="tmp_downloads",
                    help="Directorio temporal/local de trabajo (descargas o ficheros existentes).")
    ap.add_argument("--max-pages", type=int, default=2000,
                    help="Límite de páginas para el crawler.")
    ap.add_argument("--overwrite", action="store_true",
                    help="Re-descargar y/o re-convertir aunque existan archivos.")
    ap.add_argument("--inventory-csv", type=str, default="inventory_links.csv",
                    help="Ruta del inventario consolidado (enlaces, estados, rutas locales).")
    ap.add_argument("--verbose", action="store_true",
                    help="Imprimir progreso detallado y errores durante la conversión.")
    ap.add_argument("--log-file", type=str,
                    help="Ruta de archivo para guardar el log de ejecución.")
    ap.add_argument("--ephemeral", action="store_true",
                    help="Descargar a tmp-dir, convertir y borrar originales tras convertir.")
    ap.add_argument("--skip-download", action="store_true",
                    help="Saltar la descarga y convertir usando ficheros ya presentes en --tmp-dir.")
    args = ap.parse_args()

    VERBOSE = args.verbose
    EPHEMERAL = args.ephemeral
    SKIP_DOWNLOAD = args.skip_download

    # Si el usuario pide skip-download, ignoramos borrado efímero por seguridad (no se borra nada local)
    if SKIP_DOWNLOAD and EPHEMERAL:
        print("[WARN] --skip-download solicitado: se ignora --ephemeral (no se borrarán ficheros locales).", file=sys.stderr)
        EPHEMERAL = False

    # --- Configurar logging (consola + archivo opcional)
    handlers = [logging.StreamHandler(sys.stderr)]
    if args.log_file:
        log_path = Path(args.log_file)
        ensure_dir(log_path.parent)
        handlers.append(logging.FileHandler(log_path, mode="w", encoding="utf-8"))

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=handlers
    )
    log = logging.getLogger(__name__)

    out_dir = Path(args.out_dir)
    tmp_dir = Path(args.tmp_dir)
    ensure_dir(out_dir)
    ensure_dir(tmp_dir)

    resources: List[ResourceRow] = []

    # --- Modo LOCAL (NUEVO): tomar todo lo que haya en tmp-dir
    if args.from_tmp:
        log.info(f"[INFO] Cargando recursos locales desde: {tmp_dir}")
        local_rows = discover_local_resources(tmp_dir)
        resources.extend(local_rows)
        # Si sólo queremos local y además pasaron start-url/catalog, seguimos combinando;
        # quien manda es lo que se acumule en 'resources'.

    # --- Modo catálogo
    if args.catalog_file and Path(args.catalog_file).exists():
        log.info(f"[INFO] Cargando catálogo: {args.catalog_file}")
        catalog_pages = load_catalog(Path(args.catalog_file))

        direct = [r for r in catalog_pages if r.format in ("CSV", "ZIP")]
        if direct:
            log.info(f"[INFO] Enlaces directos CSV/ZIP en catálogo: {len(direct)}")
            resources.extend(direct)
        else:
            log.info("[INFO] Sin enlaces directos en catálogo. Explorando páginas…")
            page_resources = extract_csv_zip_from_pages(catalog_pages, same_host=True)
            log.info(f"[INFO] Enlaces extraídos de páginas: {len(page_resources)}")
            resources.extend(page_resources)

    # --- Modo crawler
    if args.start_url:
        log.info(f"[INFO] Rastreo desde: {args.start_url}")
        crawl_rows = crawl_for_links(args.start_url, max_pages=args.max_pages)
        log.info(f"[INFO] Crawler encontró {len(crawl_rows)} enlaces CSV/ZIP.")
        resources.extend(crawl_rows)

    # De-duplicar por URL + local_path (para no repetir locales)
    dedup = {}
    for r in resources:
        key = (r.url, r.local_path)
        dedup[key] = r
    resources = list(dedup.values())

    if not resources:
        log.warning("[WARN] No se encontraron recursos para procesar (locales ni remotos).")
        sys.exit(1)

    log.info(f"[INFO] Recursos a procesar: {len(resources)}")

    results = []
    for rr in tqdm(resources, desc="Procesando recursos", unit="res"):
        res = process_resource(rr, out_dir=out_dir, tmp_dir=tmp_dir, overwrite=args.overwrite)
        results.append(res)

    # Inventario consolidado
    inv_path = Path(args.inventory_csv)
    df_inv = pd.DataFrame([asdict(r) for r in results])
    df_inv.to_csv(inv_path, index=False, encoding="utf-8")
    log.info(f"[OK] Inventario escrito en: {inv_path}")
    log.info(f"[OK] Parquet en: {out_dir.resolve()}")


if __name__ == "__main__":
    main()

