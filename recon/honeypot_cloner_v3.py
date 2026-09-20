#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import mimetypes
import os
import re
import signal
from pathlib import Path
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse
from datetime import datetime, timezone
import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ALLOWED_SCHEMES = {"http", "https"}
IGNORED_PREFIXES = ("#", "javascript:", "mailto:", "tel:", "data:", "blob:")
STATIC_TAGS = {
    "img": "src", "script": "src", "link": "href", "source": "src",
    "video": "src", "audio": "src"
}
JS_URL_PATTERN = re.compile(r"(?P<quote>['\"])(?P<url>https?://[^'\"]+)(?P=quote)", re.I)
CSS_URL_PATTERN = re.compile(r"url\((['\"]?)(.*?)\1\)", re.I)

DEFAULT_TIMEOUT = 15
DEFAULT_MAX_DEPTH = 4
DEFAULT_MAX_FILE_SIZE = 20 * 1024 * 1024
DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36"
logger = logging.getLogger("honeypot-cloner")

@dataclass
class FetchMetadata:
    requested_url: str
    final_url: str
    status_code: int
    headers: dict[str, str]
    content_type: str

@dataclass
class ManifestEntry:
    requested_url: str
    final_url: str
    status_code: int
    content_type: str
    local_path: str
    resource_type: str
    source_scope: str
    original_headers: dict[str, str]

def normalize_url(url: str) -> str:
    url = url.strip()
    if not url:
        raise ValueError("URL vacía")
    parsed = urlparse(url)
    if not parsed.scheme:
        url = f"https://{url}"
        parsed = urlparse(url)
    if parsed.scheme.lower() not in ALLOWED_SCHEMES or not parsed.netloc:
        raise ValueError(f"URL inválida: {url}")
    path = re.sub(r"/{2,}", "/", parsed.path or "/")
    query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)))
    return urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), path, "", query, ""))

def site_slug(url: str) -> str:
    p = urlparse(url)
    host = p.hostname or "unknown"
    port = f"-{p.port}" if p.port else ""
    return re.sub(r"[^a-zA-Z0-9._-]", "-", f"{host}{port}").strip("-") or "site"

def load_recon_targets(path: Path) -> list[str]:
    if not path.exists():
        raise FileNotFoundError(path)
    values: list[str] = []
    if path.suffix.lower() == ".json":
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            items = data.get("targets") or data.get("urls") or data.get("hosts") or []
        else:
            items = []
        for item in items:
            if isinstance(item, str):
                values.append(item)
            elif isinstance(item, dict):
                value = item.get("url") or item.get("host") or item.get("target")
                if value:
                    values.append(str(value))
    else:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                values.append(line.split()[0])
    out, seen = [], set()
    for value in values:
        try:
            normalized = normalize_url(value)
        except ValueError as exc:
            logger.warning("Objetivo descartado %r: %s", value, exc)
            continue
        p = urlparse(normalized)
        root = urlunparse((p.scheme, p.netloc, "/", "", "", ""))
        if root not in seen:
            seen.add(root)
            out.append(root)
    return out

def build_session(user_agent: str) -> requests.Session:
    session = requests.Session()
    retry = Retry(total=3, connect=3, read=2, status=2, backoff_factor=0.5,
                  status_forcelist=(429, 500, 502, 503, 504),
                  allowed_methods=("GET", "HEAD"), raise_on_status=False)
    adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=20)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({
        "User-Agent": user_agent,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Encoding": "identity"
    })
    
    return session

def verify_proxy(session: requests.Session) -> None:
    try:
        response = session.get(
            "https://check.torproject.org/api/ip",
            timeout=20
        )
        response.raise_for_status()

        data = response.json()

        if not data.get("IsTor"):
            raise RuntimeError(
                "La conexión no está saliendo por Tor"
            )

        logger.info(
            "Tor operativo. Exit IP: %s",
            data.get("IP", "unknown")
        )

    except requests.RequestException as exc:
        raise RuntimeError(
            f"No se pudo validar la conexión Tor: {exc}"
        ) from exc

def write_sites_events(root: Path, results: list[dict[str, object]]) -> None:
    output = root / "sites_events.jsonl"
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    with output.open("w", encoding="utf-8") as f:
        for result in results:
            if result.get("status") != "ok":
                continue

            target = str(result["target"])
            host = urlparse(target).hostname or target

            event = {
                "@timestamp": now,
                "event": {
                    "kind": "state",
                    "category": ["configuration"],
                    "type": ["creation"],
                    "dataset": "honeypot.sites"
                },
                "honeypot": {
                    "site_id": result["site-id"],
                    "status": result["status"],
                    "original_domain": host,
                    "output_dir": str(result["output_dir"]),
                    "pages_visited": int(result.get("pages_visited", 0)),
                    "resources_downloaded": int(
                        result.get("resources_downloaded", 0)
                    ),
                    "external_references": int(
                        result.get("external_references", 0)
                    ),
                    "errors": int(result.get("errors", 0))
                },
                "tls": {
                    "verification_failed": bool(
                    result.get("tls", {}).get("verification_failed", False)
                    )
                }
            }

            f.write(json.dumps(event, ensure_ascii=False) + "\n")


class SiteCrawler:
    def __init__(self, base_url: str, output_dir: Path, mode: str, max_depth: int,
                 timeout: int, max_file_size: int, user_agent: str) -> None:
        self.base_url = normalize_url(base_url)
        self.base_netloc = urlparse(self.base_url).netloc.lower()
        self.output_dir = output_dir.resolve()
        self.mode = mode
        self.max_depth = max_depth
        self.timeout = timeout
        self.max_file_size = max_file_size
        self.session = build_session(user_agent)
        self.visited_pages: set[str] = set()
        self.downloaded_resources: set[str] = set()
        self.manifest: list[ManifestEntry] = []
        self.errors: list[dict[str, str]] = []
        self.external_references: list[dict[str, str]] = []
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.verify_tls = True
        self.tls_validation_failed = False

    def is_internal(self, url: str) -> bool:
        p = urlparse(url)
        return p.scheme in ALLOWED_SCHEMES and p.netloc.lower() == self.base_netloc

    @staticmethod
    def sanitize_segment(segment: str) -> str:
        cleaned = re.sub(r"[^a-zA-Z0-9._-]", "_", segment.strip()) or "index"

        if len(cleaned.encode("utf-8")) <= 180:
            return cleaned

        suffix = Path(cleaned).suffix
        stem = Path(cleaned).stem

        digest = hashlib.sha256(cleaned.encode()).hexdigest()[:12]

        max_stem_len = 180 - len(suffix.encode("utf-8")) - len(digest) - 1
        stem = stem[:max_stem_len]

        return f"{stem}_{digest}{suffix}"

    def normalize_reference(self, current_url: str, reference: str) -> str | None:
        reference = reference.strip()
        if not reference or reference.lower().startswith(IGNORED_PREFIXES):
            return None
        try:
            return normalize_url(urljoin(current_url, reference))
        except ValueError:
            return None

    def url_to_local_path(self, url: str, content_type: str = "", is_html: bool = False,
                          external: bool = False) -> Path:
        p = urlparse(url)
        path = p.path.lstrip("/")
        if not path:
            path = "index.html"
        elif path.endswith("/"):
            path += "index.html"
        parts = [self.sanitize_segment(x) for x in Path(path).parts if x not in {"", ".", ".."}]
        relative = Path(*parts) if parts else Path("index.html")
        if p.query:
            qh = hashlib.sha256(p.query.encode()).hexdigest()[:12]
            relative = relative.with_name(
                f"{relative.stem}_{qh}{relative.suffix}" if relative.suffix else f"{relative.name}_{qh}"
            )
        if is_html and relative.suffix.lower() not in {".html", ".htm"}:
            relative = relative / "index.html"
        if not relative.suffix and content_type:
            ext = mimetypes.guess_extension(content_type.split(";", 1)[0].strip().lower())
            if ext:
                relative = relative.with_suffix(ext)
        if external:
            relative = Path("_external") / self.sanitize_segment(p.netloc) / relative
        local = (self.output_dir / relative).resolve()
        if local != self.output_dir and self.output_dir not in local.parents:
            raise ValueError(f"Ruta insegura desde {url}")
        return local

    def local_reference(self, source_url: str, target_url: str, target_is_html: bool,
                        external: bool = False) -> str:
        # source = self.url_to_local_path(source_url, is_html=True)
        target = self.url_to_local_path(target_url, is_html=target_is_html, external=external)
        relative = target.relative_to(self.output_dir)
        return "/" + relative.as_posix().lstrip("/")
        # return Path(os.path.relpath(target, source.parent)).as_posix()

    def fetch(self, url: str) -> tuple[FetchMetadata, bytes] | None:
        try:
            try:
                r = self.session.get(
                    url,
                    timeout=(10, self.timeout),
                    stream=True,
                    allow_redirects=True,
                    verify=self.verify_tls
                )
            except requests.exceptions.SSLError as exc:

                if not self.verify_tls:
                    raise

                logger.warning(
                    "TLS validation failed for %s. "
                    "Disabling certificate validation for this site.",
                    self.base_url
                )

                self.verify_tls = False
                self.tls_validation_failed = True

                r = self.session.get(
                    url,
                    timeout=(10, self.timeout),
                    stream=True,
                    allow_redirects=True,
                    verify=False
                )

        except requests.RequestException as exc:
            self.errors.append({"url": url, "error": str(exc)})
            return None

        meta = FetchMetadata(
            url,
            r.url,
            r.status_code,
            {str(k): str(v) for k, v in r.headers.items()},
            r.headers.get("Content-Type", "")
        )

        if r.status_code >= 400:
            self.errors.append({"url": url, "error": f"HTTP {r.status_code}"})
            r.close()
            return None
        chunks, total = [], 0
        try:
            for chunk in r.iter_content(65536):
                if not chunk:
                    continue
                total += len(chunk)
                if total > self.max_file_size:
                    self.errors.append({"url": url, "error": "max_file_size exceeded"})
                    return None
                chunks.append(chunk)
        except (
            requests.exceptions.ChunkedEncodingError,
            requests.exceptions.ConnectionError,
            requests.exceptions.ReadTimeout
        ) as exc:
            logger.warning(
            "Incomplete/failed response while downloading %s: %s",
            url,
            exc
        )

            self.errors.append({
                "url": url,
                "error": str(exc),
                "type": "incomplete_response"
            })

            return None

        finally:
            r.close()
        return meta, b"".join(chunks)

    def save_bytes(self, path: Path, content: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        logger.info("Guardado %s", path)

    def add_manifest(self, meta: FetchMetadata, path: Path, resource_type: str,
                     source_scope: str) -> None:
        self.manifest.append(ManifestEntry(
            meta.requested_url, meta.final_url, meta.status_code, meta.content_type,
            str(path.relative_to(self.output_dir)), resource_type, source_scope, meta.headers
        ))

    def register_external_reference(self, source: str, url: str, ref_type: str) -> None:
        self.external_references.append({"source": source, "url": url, "type": ref_type})

    def scan_javascript(self, js_url: str, content: bytes) -> None:
        text = content.decode("utf-8", errors="replace")
        for match in JS_URL_PATTERN.finditer(text):
            try:
                url = normalize_url(match.group("url"))
            except ValueError:
                continue
            if not self.is_internal(url):
                self.register_external_reference(js_url, url, "javascript")

    def rewrite_css(self, css_url: str, content: bytes, css_external: bool) -> bytes:
        text = content.decode("utf-8", errors="replace")
        def repl(match: re.Match[str]) -> str:
            raw = match.group(2).strip()
            if not raw or raw.lower().startswith(("data:", "blob:")):
                return match.group(0)
            resolved = self.normalize_reference(css_url, raw)
            if not resolved:
                return match.group(0)
            local = self.download_resource(resolved, allow_external=True)
            if local:
                css_path = self.url_to_local_path(css_url, content_type="text/css", external=css_external)
                return f"url('{Path(os.path.relpath(local, css_path.parent)).as_posix()}')"
            self.register_external_reference(css_url, resolved, "css")
            return match.group(0) if self.mode == "faithful" else "url('')"
        return CSS_URL_PATTERN.sub(repl, text).encode("utf-8")

    def download_resource(self, url: str, allow_external: bool) -> Path | None:
        url = normalize_url(url)
        external = not self.is_internal(url)
        if external and not allow_external:
            return None
        key = f"{'ext' if external else 'int'}:{url}"
        if key in self.downloaded_resources:
            return self.url_to_local_path(url, external=external)
        self.downloaded_resources.add(key)
        fetched = self.fetch(url)
        if fetched is None:
            return None
        meta, content = fetched
        lower = meta.content_type.lower()
        if "text/css" in lower:
            content = self.rewrite_css(url, content, external)
        elif "javascript" in lower or urlparse(url).path.lower().endswith(".js"):
            self.scan_javascript(url, content)
        path = self.url_to_local_path(url, content_type=meta.content_type, external=external)
        self.save_bytes(path, content)
        self.add_manifest(meta, path, "asset", "external" if external else "internal")
        return path

    def rewrite_static_reference(self, page_url: str, original: str) -> tuple[str, bool]:
        resolved = self.normalize_reference(page_url, original)
        if not resolved:
            return original, False
        external = not self.is_internal(resolved)
        local = self.download_resource(resolved, allow_external=True)
        if local:
            return self.local_reference(page_url, resolved, False, external), True
        self.register_external_reference(page_url, resolved, "asset")
        return (original, False) if self.mode == "faithful" else ("", False)

    def process_html(self, page_url: str, meta: FetchMetadata, content: bytes, depth: int) -> None:
        soup = BeautifulSoup(content, "html.parser")
        pages: list[str] = []
        for tag in soup.find_all("base"):
            tag.decompose()
        for tag in soup.find_all("meta"):
            if str(tag.get("http-equiv", "")).lower() == "refresh":
                tag.decompose()

        for tag_name, attr in STATIC_TAGS.items():
            for tag in soup.find_all(tag_name):
                original = tag.get(attr)
                if not original:
                    continue
                new_value, localized = self.rewrite_static_reference(page_url, str(original))
                if new_value:
                    tag[attr] = new_value
                elif self.mode != "faithful":
                    tag.decompose()
                    continue
                if not localized:
                    resolved = self.normalize_reference(page_url, str(original))
                    if resolved:
                        tag["data-original-url"] = resolved

        for tag in soup.find_all("a", href=True):
            original = str(tag["href"])
            resolved = self.normalize_reference(page_url, original)
            if not resolved:
                continue
            if self.is_internal(resolved):
                tag["href"] = self.local_reference(page_url, resolved, True)
                pages.append(resolved)
            else:
                self.register_external_reference(page_url, resolved, "link")
                if self.mode != "faithful":
                    tag["data-original-url"] = resolved
                    tag["href"] = "#"

        for form in soup.find_all("form"):
            original = str(form.get("action", ""))
            resolved = self.normalize_reference(page_url, original) if original else None
            if resolved:
                form["data-original-action"] = resolved
            form["action"] = "/__honeypot__/capture"
            form["method"] = str(form.get("method", "post")).lower()
            form["data-honeypot-form"] = "true"

        for tag in soup.find_all(style=True):
            style = str(tag["style"])
            def repl(match: re.Match[str]) -> str:
                raw = match.group(2).strip()
                if not raw or raw.lower().startswith(("data:", "blob:")):
                    return match.group(0)
                resolved = self.normalize_reference(page_url, raw)
                if not resolved:
                    return match.group(0)
                external = not self.is_internal(resolved)
                local = self.download_resource(resolved, allow_external=True)
                if local:
                    return f"url('{self.local_reference(page_url, resolved, False, external)}')"
                self.register_external_reference(page_url, resolved, "inline-style")
                return match.group(0) if self.mode == "faithful" else "url('')"
            tag["style"] = CSS_URL_PATTERN.sub(repl, style)

        path = self.url_to_local_path(page_url, content_type="text/html", is_html=True)
        self.save_bytes(path, soup.encode("utf-8", formatter="html"))
        self.add_manifest(meta, path, "html", "internal")
        for target in pages:
            self.crawl(target, depth + 1)

    def crawl(self, url: str, depth: int = 0) -> None:
        url = normalize_url(url)
        if depth > self.max_depth or url in self.visited_pages or not self.is_internal(url):
            return
        self.visited_pages.add(url)
        fetched = self.fetch(url)
        if fetched is None:
            return
        meta, content = fetched
        if "text/html" in meta.content_type.lower():
            self.process_html(url, meta, content, depth)
        else:
            path = self.url_to_local_path(url, content_type=meta.content_type)
            self.save_bytes(path, content)
            self.add_manifest(meta, path, "document", "internal")

    def save_reports(self) -> None:
        (self.output_dir / "manifest.json").write_text(
            json.dumps([asdict(x) for x in self.manifest], indent=2, ensure_ascii=False), encoding="utf-8")
        (self.output_dir / "errors.json").write_text(
            json.dumps(self.errors, indent=2, ensure_ascii=False), encoding="utf-8")
        (self.output_dir / "external_references.json").write_text(
            json.dumps(self.external_references, indent=2, ensure_ascii=False), encoding="utf-8")
        summary = {
            "base_url": self.base_url,
            "mode": self.mode,
            "pages_visited": len(self.visited_pages),
            "resources_downloaded": len(self.downloaded_resources),
            "manifest_entries": len(self.manifest),
            "external_references": len(self.external_references),
            "errors": len(self.errors),
        }
        (self.output_dir / "summary.json").write_text(
            json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

def write_global_summary(root: Path, targets: list[str], results: list[dict[str, object]]) -> None:
    data = {
        "detected_site_count": len(targets),
        "mode": "single-site" if len(targets) == 1 else "multi-site",
        "targets": targets,
        "results": results,
    }
    (root / "recon_summary.json").write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Clonador autorizado para honeypots")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--url")
    src.add_argument("--recon-file", type=Path)
    p.add_argument("--mode", choices=("isolated", "faithful"), default="isolated")
    p.add_argument("--output", type=Path, default=Path("./cloned-sites"))
    p.add_argument("--max-depth", type=int, default=DEFAULT_MAX_DEPTH)
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    p.add_argument("--max-file-size", type=int, default=DEFAULT_MAX_FILE_SIZE)
    p.add_argument("--user-agent", default=DEFAULT_USER_AGENT)
    return p.parse_args()

def signal_handler(sig: int, frame: object) -> None:
    raise SystemExit(130)

def site_id(url: str) -> str:
    normalized = normalize_url(url)

    digest = hashlib.sha256(
        normalized.encode("utf-8")
    ).hexdigest()[:12]

    return f"site-{digest}"

def main() -> int:
    args = parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    args.output.mkdir(parents=True, exist_ok=True)
    targets = [normalize_url(args.url)] if args.url else load_recon_targets(args.recon_file)
    if not targets:
        write_global_summary(args.output, [], [])
        logger.error("El recon no produjo sitios válidos")
        return 2
    logger.info("Recon: %s", "un sitio" if len(targets) == 1 else f"{len(targets)} sitios")
    results = []
    for idx, target in enumerate(targets, 1):
        out = args.output / site_slug(target)
        logger.info("[%d/%d] %s", idx, len(targets), target)
        crawler = SiteCrawler(target, out, args.mode, args.max_depth, args.timeout,
                              args.max_file_size, args.user_agent)
        try:
            crawler.crawl(target)
            crawler.save_reports()
            results.append({

                "site-id": site_id(target),"target": target, "output_dir": str(out), "status": "ok",
                "pages_visited": len(crawler.visited_pages),
                "resources_downloaded": len(crawler.downloaded_resources),
                "external_references": len(crawler.external_references),
                "errors": len(crawler.errors),
                "tls": {
                "verification_failed": crawler.tls_validation_failed
                }
            })
        except Exception as exc:
            logger.exception("Falló %s", target)
            results.append({"target": target, "output_dir": str(out), "status": "failed", "error": str(exc)})
    write_global_summary(args.output, targets, results)
    write_sites_events(args.output, results)
    successful = sum(1 for x in results if x.get("status") == "ok")
    if successful == 0:
        logger.error("Todos los targets fallaron de forma fatal")
        return 1

    failed = len(results) - successful
    if failed:
        logger.warning(
            "Crawl terminado con %d target(s) fatalmente fallidos y %d correctos; "
            "se continúa el pipeline.",
            failed, successful
        )

    return 0

if __name__ == "__main__":
    raise SystemExit(main())


