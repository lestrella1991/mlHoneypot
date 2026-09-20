#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from urllib.parse import urlparse


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Genera un archivo de configuración Nginx por cada sitio clonado, "
            "más un nginx.conf principal estático."
        )
    )
    parser.add_argument("--recon-summary", type=Path, required=True)
    parser.add_argument("--sites-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--listen-port", type=int, default=8080)
    return parser.parse_args()


def safe_host(url: str) -> str:
    host = urlparse(url).hostname or ""
    if not host:
        raise ValueError(f"No se pudo obtener el host desde: {url}")
    if not re.fullmatch(r"[A-Za-z0-9.-]+", host):
        raise ValueError(f"Host inválido: {host}")
    return host.lower()


def safe_slug(value: str) -> str:
    slug = Path(value).name
    if not re.fullmatch(r"[A-Za-z0-9._-]+", slug):
        raise ValueError(f"Slug inválido: {slug}")
    return slug


def nginx_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def build_main_config() -> str:
    return '''user nginx;
worker_processes auto;

error_log /var/log/nginx/error.log notice;
pid /var/run/nginx.pid;

events {
    worker_connections 1024;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    log_format honeypot_json escape=json
    '{'
      '"@timestamp":"$time_iso8601",'
      '"event":{'
        '"kind":"event",'
        '"category":["web","network"],'
        '"type":["access"],'
        '"dataset":"honeypot.nginx"'
      '},'
      '"source":{'
        '"ip":"$remote_addr",'
        '"port":"$remote_port"'
      '},'
      '"destination":{'
        '"ip":"$server_addr",'
        '"port":"$server_port"'
      '},'
      '"network":{'
        '"transport":"tcp",'
        '"protocol":"http",'
        '"direction":"inbound"'
      '},'
      '"http":{'
        '"request":{'
          '"method":"$request_method"'
        '},'
        '"response":{'
          '"status_code":"$status",'
          '"body":{'
            '"bytes":"$body_bytes_sent"'
          '}'
        '}'
      '},'
      '"url":{'
        '"domain":"$host",'
        '"path":"$uri",'
        '"original":"$request_uri"'
      '},'
      '"user_agent":{'
        '"original":"$http_user_agent"'
      '},'
      '"honeypot":{'
        '"site_id":"$honeypot_site_id",'
        '"original_domain":"$honeypot_original_domain",'
        '"clone_domain":"$host"'
      '}'
    '}';

    sendfile on;
    keepalive_timeout 65;
    server_tokens off;

    include /etc/nginx/generated/sites/*.conf;
    include /etc/nginx/conf.d/*.conf;
}

'''


def build_default_server(first_slug: str, listen_port: int) -> str:
    root = f"/usr/share/nginx/sites/{first_slug}"
    return f'''server {{
    listen {listen_port} default_server;
    server_name _;

    root {nginx_escape(root)};
    index index.html;

    location = /__health {{
        access_log off;
        default_type text/plain;
        return 200 "ok\\n";
    }}

    location / {{
        try_files $uri $uri/ =404;
    }}
}}
'''


def build_site_server(
    host: str,
    slug: str,
    site_id: str,
    listen_port: int
    ) -> str:
    root = f"/usr/share/nginx/sites/{slug}"
    return f'''server {{
    listen {listen_port};
    server_name {nginx_escape(host)};

    set $honeypot_site_id "{nginx_escape(site_id)}";
    set $honeypot_original_domain "{nginx_escape(host)}";

    root {nginx_escape(root)};
    index index.html;

    access_log /var/log/nginx/honeypot_access.json honeypot_json;
    error_log /var/log/nginx/{nginx_escape(slug)}.error.log warn;

    location = /__health {{
        access_log off;
        default_type text/plain;
        return 200 "ok\\n";
    }}

    location = /__honeypot__/capture {{
        default_type application/json;
        return 200 '{{"status":"received"}}';
    }}

    location / {{
        try_files $uri $uri/ =404;
    }}
}}
'''

def build_kibana():
    return f'''server {{
    listen 5601;
    server_name kibana.local;

    root /usr/share/nginx/sites/kibana.local;
    index index.html;

    access_log /var/log/nginx/kibana.local.access.log main;
    error_log /var/log/nginx/kibana.local.error.log warn;

    location = /__health {{
        access_log off;
        default_type text/plain;
        return 200 "ok\\n";
    }}

    location / {{
        try_files $uri $uri/ =404;
    }}
}}
'''

def build_proxy_config() -> str:
    return '''user nginx;
worker_processes auto;

events {
    worker_connections 1024;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    upstream cloned_sites {
        server sites:8080;
        keepalive 16;
    }

    server {
        listen 80 default_server;
        server_name _;

        location = /__health {
            access_log off;
            default_type text/plain;
            return 200 "ok\\n";
        }

        location / {
            proxy_pass http://cloned_sites;

            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header Connection "";
        }
    }
}
'''


def write_atomic(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_suffix(path.suffix + ".tmp")
    temp_path.write_text(content, encoding="utf-8")
    temp_path.replace(path)


def main() -> int:
    args = parse_args()

    if not args.recon_summary.is_file():
        raise SystemExit(f"No existe el archivo de resumen: {args.recon_summary}")
    if not args.sites_root.is_dir():
        raise SystemExit(f"No existe el directorio de sitios: {args.sites_root}")
    if args.listen_port < 1 or args.listen_port > 65535:
        raise SystemExit(f"Puerto inválido: {args.listen_port}")

    try:
        data = json.loads(args.recon_summary.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"JSON inválido en {args.recon_summary}: {exc}") from exc

    results = [r for r in data.get("results", []) if r.get("status") == "ok"]
    if not results:
        raise SystemExit("No hay clones exitosos")

    output_root = args.output.resolve()
    generated_sites_dir = output_root / "sites"
    output_root.mkdir(parents=True, exist_ok=True)
    generated_sites_dir.mkdir(parents=True, exist_ok=True)

    for old_config in generated_sites_dir.glob("*.conf"):
        old_config.unlink()

    generated_metadata: list[dict[str, str]] = []

    for result in results:
        target = str(result["target"])
        host = safe_host(target)
        slug = safe_slug(str(result["output_dir"]))
        site_id = str(result["site-id"])

        local_site_dir = args.sites_root / slug

        if not local_site_dir.is_dir():
            raise SystemExit(f"El sitio clonado no existe en disco: {local_site_dir}")

        site_config_path = generated_sites_dir / f"{slug}.conf"
        write_atomic(
            site_config_path,
            build_site_server(
                host=host, 
                slug=slug,
                site_id=site_id, 
                listen_port=args.listen_port
            ),
        )

        generated_metadata.append({
            "site_id": site_id,
            "host": host,
            "slug": slug,
            "config": str(site_config_path),
            "root": f"/usr/share/nginx/sites/{slug}",
        })

    first_slug = generated_metadata[0]["slug"]
    write_atomic(output_root / "nginx.conf", build_main_config())
    write_atomic(output_root / "proxy.conf",build_proxy_config())
    write_atomic(
        generated_sites_dir / "00-default.conf",
        build_default_server(first_slug=first_slug, listen_port=args.listen_port),
    )
    #write_atomic( generated_sites_dir / "kibana.local.conf" , build_kibana())

    inventory = {
        "listen_port": args.listen_port,
        "site_count": len(generated_metadata),
        "sites": generated_metadata,
    }
    write_atomic(
        output_root / "inventory.json",
        json.dumps(inventory, indent=2, ensure_ascii=False) + "\n",
    )

    print(f"[nginx] Configuración principal: {output_root / 'nginx.conf'}")
    print(f"[nginx] Configuraciones por sitio: {generated_sites_dir}")
    print(f"[nginx] Sitios generados: {len(generated_metadata)}")
    print(f"[nginx] Puerto backend: {args.listen_port}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
