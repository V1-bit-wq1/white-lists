#!/usr/bin/env python3
"""
update_whitelist.py
Скрипт для сборки подписки обхода белых списков.
Запускается из GitHub Actions, результат кладёт в папку public/.
"""

import base64
import os
import re
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

# === Источники подписок (можно добавлять/менять) ===
SOURCES = [
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_lite.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Cable.txt",
    "https://raw.githubusercontent.com/LowiKLive/BypassWhitelistRu/refs/heads/main/WhiteList-Bypass_Ru.txt",
]

# Поддерживаемые протоколы
PROTOCOLS = ("vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://", "tuic://")

OUTPUT_DIR = Path("public")
TIMEOUT = 15


def fetch_url(url: str) -> str:
    """Скачивает содержимое URL. Возвращает пустую строку при ошибке."""
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (compatible; whitelist-updater/1.0)"},
        )
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            data = resp.read()
            # Пробуем декодировать как текст
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                # Возможно base64-подписка
                try:
                    text = base64.b64decode(data).decode("utf-8")
                except Exception:
                    return ""
            return text
    except Exception as e:
        print(f"[!] Ошибка загрузки {url}: {e}")
        return ""


def extract_configs(text: str) -> list[str]:
    """Извлекает строки конфигов из текста (поддерживает base64 и plain)."""
    lines = []

    # Сначала пробуем как обычный текст
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if any(line.lower().startswith(p) for p in PROTOCOLS):
            lines.append(line)

    # Если ничего не нашли — пробуем base64
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
    """Убирает дубликаты (по полному URI)."""
    seen = set()
    result = []
    for cfg in configs:
        key = cfg.strip()
        if key not in seen:
            seen.add(key)
            result.append(key)
    return result


def write_file(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    print(f"[+] Записано: {path} ({len(content)} байт)")


def main() -> None:
    print("=" * 50)
    print("Обновление подписки белых списков")
    print(f"Время: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print("=" * 50)

    all_configs: list[str] = []

    for url in SOURCES:
        print(f"[*] Загрузка: {url}")
        text = fetch_url(url)
        if not text:
            continue
        configs = extract_configs(text)
        print(f"    найдено: {len(configs)}")
        all_configs.extend(configs)

    unique = deduplicate(all_configs)
    print(f"\n[*] Всего уникальных конфигов: {len(unique)}")

    # Создаём папку public
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Plain-text подписка
    plain_content = "\n".join(unique) + "\n"
    write_file(OUTPUT_DIR / "subscription.txt", plain_content)

    # 2. Base64-подписка (стандарт для многих клиентов)
    b64_content = base64.b64encode(plain_content.encode("utf-8")).decode("ascii")
    write_file(OUTPUT_DIR / "subscription.b64", b64_content)

    # 3. Только VLESS
    vless_only = [c for c in unique if c.lower().startswith("vless://")]
    write_file(OUTPUT_DIR / "vless.txt", "\n".join(vless_only) + "\n")
    write_file(
        OUTPUT_DIR / "vless.b64",
        base64.b64encode(("\n".join(vless_only) + "\n").encode()).decode(),
    )

    # 4. index.html — простая страница с ссылками
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    html = f"""<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>White-lists Subscription</title>
  <style>
    body {{ font-family: system-ui, sans-serif; max-width: 700px; margin: 40px auto; padding: 0 16px; }}
    h1 {{ font-size: 1.5rem; }}
    a {{ color: #0969da; word-break: break-all; }}
    .meta {{ color: #666; font-size: 0.9rem; }}
    code {{ background: #f6f8fa; padding: 2px 6px; border-radius: 4px; }}
  </style>
</head>
<body>
  <h1>Подписка для обхода белых списков</h1>
  <p class="meta">Обновлено: {now} · Конфигов: {len(unique)} (VLESS: {len(vless_only)})</p>

  <h2>Ссылки на подписку</h2>
  <ul>
    <li><a href="subscription.txt">subscription.txt</a> (plain)</li>
    <li><a href="subscription.b64">subscription.b64</a> (base64)</li>
    <li><a href="vless.txt">vless.txt</a> (только VLESS)</li>
    <li><a href="vless.b64">vless.b64</a> (VLESS base64)</li>
  </ul>

  <h2>Как добавить</h2>
  <p>Скопируйте одну из ссылок выше и добавьте как подписку в клиент<br>
  (v2rayNG, Hiddify, Streisand, Nekobox и т.д.).</p>

  <p class="meta">Автообновление каждые 30 минут через GitHub Actions.</p>
</body>
</html>
"""
    write_file(OUTPUT_DIR / "index.html", html)

    print("\nГотово.")


if __name__ == "__main__":
    main()
