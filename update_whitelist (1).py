#!/usr/bin/env python3
"""
update_whitelist.py
Сборка подписки для обхода белых списков.
Генерирует:
  - Clash YAML с группой «Автовыбор» (url-test)
  - Обычные txt / base64 подписки
Результат → папка public/ (для GitHub Pages)
"""

import base64
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# === Источники ===
SOURCES = [
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_lite.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Cable.txt",
    "https://raw.githubusercontent.com/LowiKLive/BypassWhitelistRu/refs/heads/main/WhiteList-Bypass_Ru.txt",
]

PROTOCOLS = ("vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://")

OUTPUT_DIR = Path("public")
TIMEOUT = 15
MAX_PROXIES = 80  # чтобы YAML не был слишком большим


def fetch_url(url: str) -> str:
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (compatible; whitelist-updater/1.1)"},
        )
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            data = resp.read()
            try:
                return data.decode("utf-8")
            except UnicodeDecodeError:
                try:
                    return base64.b64decode(data).decode("utf-8")
                except Exception:
                    return ""
    except Exception as e:
        print(f"[!] Ошибка {url}: {e}")
        return ""


def extract_raw_configs(text: str) -> list[str]:
    lines = []
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#") and any(line.lower().startswith(p) for p in PROTOCOLS):
            lines.append(line)

    if not lines:
        try:
            decoded = base64.b64decode(text.strip()).decode("utf-8", errors="ignore")
            for line in decoded.splitlines():
                line = line.strip()
                if line and any(line.lower().startswith(p) for p in PROTOCOLS):
                    lines.append(line)
        except Exception:
            pass
    return lines


def deduplicate(configs: list[str]) -> list[str]:
    seen: set[str] = set()
    result = []
    for cfg in configs:
        key = cfg.strip()
        if key not in seen:
            seen.add(key)
            result.append(key)
    return result


def parse_vless(uri: str) -> dict[str, Any] | None:
    """Парсит vless:// в словарь Clash."""
    try:
        if not uri.lower().startswith("vless://"):
            return None

        name = "VLESS"
        if "#" in uri:
            uri, frag = uri.rsplit("#", 1)
            name = urllib.parse.unquote(frag).strip() or name

        body = uri[8:]
        if "?" in body:
            main, query = body.split("?", 1)
            params = dict(urllib.parse.parse_qsl(query))
        else:
            main, params = body, {}

        if "@" not in main:
            return None
        uuid, server_port = main.rsplit("@", 1)
        if ":" not in server_port:
            return None
        server, port_s = server_port.rsplit(":", 1)
        port = int(port_s)

        proxy: dict[str, Any] = {
            "name": name[:64],
            "type": "vless",
            "server": server,
            "port": port,
            "uuid": uuid,
            "udp": True,
            "tls": False,
            "network": params.get("type", "tcp"),
        }

        encryption = params.get("encryption", "none")
        if encryption and encryption != "none":
            proxy["encryption"] = encryption

        flow = params.get("flow")
        if flow:
            proxy["flow"] = flow

        security = params.get("security", "").lower()
        if security in ("tls", "reality"):
            proxy["tls"] = True
            if params.get("sni"):
                proxy["servername"] = params["sni"]
            if params.get("fp"):
                proxy["client-fingerprint"] = params["fp"]
            if security == "reality":
                proxy["reality-opts"] = {}
                if params.get("pbk"):
                    proxy["reality-opts"]["public-key"] = params["pbk"]
                if params.get("sid"):
                    proxy["reality-opts"]["short-id"] = params["sid"]

        net = proxy["network"]
        if net == "ws":
            proxy["ws-opts"] = {"path": params.get("path", "/")}
            if params.get("host"):
                proxy["ws-opts"]["headers"] = {"Host": params["host"]}
        elif net == "grpc":
            proxy["grpc-opts"] = {
                "grpc-service-name": params.get("serviceName", params.get("servicename", "")),
            }
        elif net == "h2":
            proxy["h2-opts"] = {"path": params.get("path", "/")}
            if params.get("host"):
                proxy["h2-opts"]["host"] = [params["host"]]

        if params.get("packetEncoding") or params.get("packetencoding"):
            proxy["packet-encoding"] = params.get("packetEncoding") or params.get("packetencoding")

        return proxy
    except Exception as e:
        print(f"    [parse vless] {e}")
        return None


def parse_trojan(uri: str) -> dict[str, Any] | None:
    try:
        if not uri.lower().startswith("trojan://"):
            return None
        name = "Trojan"
        if "#" in uri:
            uri, frag = uri.rsplit("#", 1)
            name = urllib.parse.unquote(frag).strip() or name

        body = uri[9:]
        if "?" in body:
            main, query = body.split("?", 1)
            params = dict(urllib.parse.parse_qsl(query))
        else:
            main, params = body, {}

        if "@" not in main:
            return None
        password, server_port = main.rsplit("@", 1)
        if ":" not in server_port:
            return None
        server, port_s = server_port.rsplit(":", 1)

        proxy: dict[str, Any] = {
            "name": name[:64],
            "type": "trojan",
            "server": server,
            "port": int(port_s),
            "password": password,
            "udp": True,
        }
        if params.get("sni"):
            proxy["sni"] = params["sni"]
        if params.get("fp"):
            proxy["client-fingerprint"] = params["fp"]
        return proxy
    except Exception:
        return None


def parse_ss(uri: str) -> dict[str, Any] | None:
    try:
        if not uri.lower().startswith("ss://"):
            return None
        name = "SS"
        if "#" in uri:
            uri, frag = uri.rsplit("#", 1)
            name = urllib.parse.unquote(frag).strip() or name

        body = uri[5:]
        if "@" in body:
            userinfo, server_port = body.rsplit("@", 1)
            try:
                decoded = base64.urlsafe_b64decode(userinfo + "==").decode()
            except Exception:
                decoded = userinfo
            if ":" not in decoded:
                return None
            method, password = decoded.split(":", 1)
            if ":" not in server_port:
                return None
            server, port_s = server_port.rsplit(":", 1)
        else:
            try:
                decoded = base64.urlsafe_b64decode(body + "==").decode()
            except Exception:
                return None
            if "@" not in decoded or ":" not in decoded:
                return None
            method_pass, server_port = decoded.rsplit("@", 1)
            method, password = method_pass.split(":", 1)
            server, port_s = server_port.rsplit(":", 1)

        return {
            "name": name[:64],
            "type": "ss",
            "server": server,
            "port": int(port_s),
            "cipher": method,
            "password": password,
            "udp": True,
        }
    except Exception:
        return None


def to_clash_proxy(uri: str) -> dict[str, Any] | None:
    lower = uri.lower()
    if lower.startswith("vless://"):
        return parse_vless(uri)
    if lower.startswith("trojan://"):
        return parse_trojan(uri)
    if lower.startswith("ss://"):
        return parse_ss(uri)
    return None


def yaml_escape(s: str) -> str:
    if any(c in s for c in (":", "#", "{", "}", "[", "]", ",", "&", "*", "!", "|", ">", "'", '"', "%", "@", "`")):
        return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return s


def dict_to_yaml(obj: Any, indent: int = 0) -> str:
    sp = "  " * indent
    if isinstance(obj, dict):
        lines = []
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                lines.append(f"{sp}{k}:")
                lines.append(dict_to_yaml(v, indent + 1))
            elif isinstance(v, bool):
                lines.append(f"{sp}{k}: {'true' if v else 'false'}")
            elif isinstance(v, (int, float)):
                lines.append(f"{sp}{k}: {v}")
            elif v is None:
                lines.append(f"{sp}{k}: null")
            else:
                lines.append(f"{sp}{k}: {yaml_escape(str(v))}")
        return "\n".join(lines)
    if isinstance(obj, list):
        lines = []
        for item in obj:
            if isinstance(item, dict):
                first = True
                for k, v in item.items():
                    if first:
                        if isinstance(v, (dict, list)):
                            lines.append(f"{sp}- {k}:")
                            lines.append(dict_to_yaml(v, indent + 2))
                        elif isinstance(v, bool):
                            lines.append(f"{sp}- {k}: {'true' if v else 'false'}")
                        elif isinstance(v, (int, float)):
                            lines.append(f"{sp}- {k}: {v}")
                        else:
                            lines.append(f"{sp}- {k}: {yaml_escape(str(v))}")
                        first = False
                    else:
                        if isinstance(v, (dict, list)):
                            lines.append(f"{sp}  {k}:")
                            lines.append(dict_to_yaml(v, indent + 2))
                        elif isinstance(v, bool):
                            lines.append(f"{sp}  {k}: {'true' if v else 'false'}")
                        elif isinstance(v, (int, float)):
                            lines.append(f"{sp}  {k}: {v}")
                        else:
                            lines.append(f"{sp}  {k}: {yaml_escape(str(v))}")
            else:
                lines.append(f"{sp}- {yaml_escape(str(item))}")
        return "\n".join(lines)
    return f"{sp}{yaml_escape(str(obj))}"


def build_clash_yaml(proxies: list[dict[str, Any]]) -> str:
    seen: dict[str, int] = {}
    unique_proxies = []
    for p in proxies:
        n = p["name"]
        if n in seen:
            seen[n] += 1
            p = dict(p)
            p["name"] = f"{n} ({seen[n]})"
        else:
            seen[n] = 1
        unique_proxies.append(p)

    names = [p["name"] for p in unique_proxies]

    config = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "external-controller": "127.0.0.1:9090",
        "dns": {
            "enable": True,
            "enhanced-mode": "fake-ip",
            "nameserver": [
                "8.8.8.8",
                "1.1.1.1",
                "https://dns.google/dns-query",
            ],
        },
        "proxies": unique_proxies,
        "proxy-groups": [
            {
                "name": "🚀 Автовыбор",
                "type": "url-test",
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300,
                "tolerance": 50,
                "lazy": True,
                "proxies": names,
            },
            {
                "name": "♻️ Fallback",
                "type": "fallback",
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300,
                "proxies": names,
            },
            {
                "name": "📶 PROXY",
                "type": "select",
                "proxies": ["🚀 Автовыбор", "♻️ Fallback"] + names,
            },
        ],
        "rules": [
            "GEOIP,RU,DIRECT",
            "GEOIP,LAN,DIRECT",
            "MATCH,📶 PROXY",
        ],
    }

    header = (
        f"# White-lists Clash subscription\n"
        f"# Updated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n"
        f"# Proxies: {len(unique_proxies)}\n"
        f"#profile-title: Белые списки — Автовыбор\n"
        f"#profile-update-interval: 1\n\n"
    )
    return header + dict_to_yaml(config) + "\n"


def write_file(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    print(f"[+] {path} ({len(content)} байт)")


def main() -> None:
    print("=" * 55)
    print("Обновление подписки (Clash + plain)")
    print(f"Время: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print("=" * 55)

    all_raw: list[str] = []
    for url in SOURCES:
        print(f"[*] {url}")
        text = fetch_url(url)
        if not text:
            continue
        configs = extract_raw_configs(text)
        print(f"    → {len(configs)} шт.")
        all_raw.extend(configs)

    unique_raw = deduplicate(all_raw)
    print(f"\n[*] Уникальных ссылок: {len(unique_raw)}")

    proxies: list[dict[str, Any]] = []
    for uri in unique_raw:
        p = to_clash_proxy(uri)
        if p:
            proxies.append(p)
        if len(proxies) >= MAX_PROXIES:
            break

    print(f"[*] Успешно распарсено в Clash: {len(proxies)}")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Clash YAML с автовыбором
    clash_yaml = build_clash_yaml(proxies)
    write_file(OUTPUT_DIR / "clash.yaml", clash_yaml)

    # 2. Plain-text
    plain = "\n".join(unique_raw) + "\n"
    write_file(OUTPUT_DIR / "subscription.txt", plain)
    write_file(
        OUTPUT_DIR / "subscription.b64",
        base64.b64encode(plain.encode()).decode(),
    )

    vless_only = [c for c in unique_raw if c.lower().startswith("vless://")]
    write_file(OUTPUT_DIR / "vless.txt", "\n".join(vless_only) + "\n")
    write_file(
        OUTPUT_DIR / "vless.b64",
        base64.b64encode(("\n".join(vless_only) + "\n").encode()).decode(),
    )

    # 3. index.html
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    html = f"""<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>White-lists — Автовыбор</title>
  <style>
    body {{ font-family: system-ui, sans-serif; max-width: 720px; margin: 40px auto; padding: 0 16px; line-height: 1.5; }}
    h1 {{ font-size: 1.4rem; }}
    a {{ color: #0969da; word-break: break-all; }}
    .meta {{ color: #666; font-size: 0.9rem; }}
    code {{ background: #f6f8fa; padding: 2px 6px; border-radius: 4px; font-size: 0.9em; }}
    .card {{ background: #f6f8fa; border-radius: 8px; padding: 14px 16px; margin: 12px 0; }}
  </style>
</head>
<body>
  <h1>Подписка для обхода белых списков</h1>
  <p class="meta">Обновлено: {now} · Конфигов: {len(unique_raw)} · Clash-прокси: {len(proxies)}</p>

  <div class="card">
    <strong>🚀 Clash / Mihomo / Hiddify (с автовыбором)</strong><br>
    <a href="clash.yaml">clash.yaml</a>
  </div>

  <div class="card">
    <strong>Обычная подписка (v2rayNG, Streisand…)</strong><br>
    <a href="subscription.txt">subscription.txt</a> ·
    <a href="subscription.b64">subscription.b64</a><br>
    <a href="vless.txt">vless.txt</a> ·
    <a href="vless.b64">vless.b64</a>
  </div>

  <h2>Как добавить Clash-подписку</h2>
  <ol>
    <li>Скопируйте ссылку: <code>https://v1-bit-wq1.github.io/white-lists/clash.yaml</code></li>
    <li>В Clash Verge / Mihomo / Hiddify → Профили → Импорт из URL</li>
    <li>В группе <strong>📶 PROXY</strong> выберите <strong>🚀 Автовыбор</strong></li>
  </ol>

  <p class="meta">Автообновление каждые 30 минут.</p>
</body>
</html>
"""
    write_file(OUTPUT_DIR / "index.html", html)

    print("\nГотово.")


if __name__ == "__main__":
    main()
