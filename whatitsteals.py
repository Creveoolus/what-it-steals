#!/usr/bin/env python3
"""
WhatItSteals - показывает жертве стиллера, какие данные потенциально были украдены.

Важно: приложение НИКОГДА не извлекает и не отображает секретные значения
(пароли, токены, seed-фразы, приватные ключи). Только метаданные:
количество записей, домены, имена файлов, даты. Это делает отчёт
бесполезным для мошенников, но полезным для жертвы.
"""

import argparse
import glob
import html
import json
import os
import platform
import sqlite3
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlparse

APP_NAME = "WhatItSteals"
APP_VERSION = "1.0.0"

# ══════════════════════════ МОДЕЛИ ══════════════════════════

SEVERITY_INFO = "info"       # ничего ценного
SEVERITY_MEDIUM = "medium"   # чувствительные данные
SEVERITY_HIGH = "high"       # пароли/токены/крипта
SEVERITY_CRITICAL = "critical"  # крипта, seed-фразы

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "info": 3}


@dataclass
class Finding:
    """Один найденный 'таргет' - то, что стиллер мог украсть."""
    category: str          # браузеры / крипта / мессенджеры / ...
    title: str             # человекочитаемое название
    severity: str          # info/medium/high/critical
    details: list = field(default_factory=list)   # строки с деталями (маскированные)
    evidence: str = ""     # путь-доказательство (не секрет сам по себе)
    count: int = 0         # число записей, если применимо


def mask_login(login: str) -> str:
    """Маскирует логин: user@gmail.com -> u***@gmail.com"""
    if not login:
        return "***"
    if len(login) <= 2:
        return login[0] + "***"
    return login[0] + "***" + login[-4:] if len(login) > 6 else login[0] + "***"


def domain_of(url: str) -> str:
    try:
        p = urlparse(url if "//" in url else "https://" + url)
        return p.netloc or p.path.split("/")[0]
    except Exception:
        return url[:40]


def walk_bounded(root: str, max_depth=3, max_files=5000, patterns=None, timeout=10):
    """Безопасный обход дерева: ограничение глубины, числа файлов, symlink-циклов и времени."""
    start = time.time()
    root = os.path.abspath(root)
    root_depth = root.rstrip(os.sep).count(os.sep)
    hits = []
    n = 0
    for dirpath, dirs, files in os.walk(root, followlinks=False):
        # не спускаемся глубже max_depth
        if dirpath.rstrip(os.sep).count(os.sep) - root_depth >= max_depth:
            dirs[:] = []
        # пропускаем симлинки на директории (защита от циклов)
        dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(dirpath, d))]
        for fn in files:
            n += 1
            if n > max_files or (time.time() - start) > timeout:
                return hits
            if patterns is None:
                hits.append(os.path.join(dirpath, fn))
            elif any(p in fn.lower() for p in patterns):
                hits.append(os.path.join(dirpath, fn))
    return hits


# ══════════════════════════ БРАУЗЕРЫ ══════════════════════════

# Chromium-браузеры: имя -> пути по ОС (относительно базовой директории профиля)
# win: %LOCALAPPDATA%/<rel>/User Data | linux: ~/.config/<rel> | mac: ~/Library/Application Support/<rel>
CHROMIUM_BROWSERS = {
    "Google Chrome":   {"win": "Google/Chrome",   "linux": "google-chrome",              "mac": "Google/Chrome"},
    "Microsoft Edge":  {"win": "Microsoft/Edge",   "linux": "microsoft-edge",             "mac": "Microsoft Edge"},
    "Brave":           {"win": "BraveSoftware/Brave-Browser", "linux": "BraveSoftware/Brave-Browser", "mac": "BraveSoftware/Brave-Browser"},
    "Opera":           {"win": "Opera Software/Opera Stable", "linux": "opera",           "mac": "com.operasoftware.Opera"},
    "Opera GX":        {"win": "Opera Software/Opera GX Stable", "linux": None,           "mac": None},
    "Yandex Browser":  {"win": "Yandex/YandexBrowser", "linux": "yandex-browser",         "mac": "Yandex/YandexBrowser"},
    "Vivaldi":         {"win": "Vivaldi",          "linux": "vivaldi",                     "mac": "Vivaldi"},
    "Chromium":        {"win": "Chromium",         "linux": "chromium",                    "mac": "Chromium"},
    "CocCoc":          {"win": "BrowserCore",     "linux": "coccoc",                      "mac": None},
    "Maxthon":         {"win": "Maxthon",         "linux": "maxthon",                     "mac": None},
}

# Альтернативные Discord-клиенты (токены живут там же, в Local Storage leveldb)
DISCORD_CLIENTS = {
    "Discord":          {"win": "discord",   "linux": "discord",   "mac": "discord"},
    "Vesktop":          {"win": "Vesktop",   "linux": "vesktop",   "mac": "Vesktop"},
    "WebCord":          {"win": "WebCord",   "linux": "WebCord",   "mac": "WebCord"},
    "ArmCord":          {"win": "ArmCord",   "linux": "ArmCord",   "mac": "ArmCord"},
}

# Telegram-клиенты: сессии (tdata) у всех в своих папках
TELEGRAM_CLIENTS = {
    "Telegram Desktop": {"win": "Telegram Desktop", "linux": "TelegramDesktop", "mac": "Telegram Desktop"},
    "AyuGram":          {"win": "AyuGram",          "linux": "AyuGramDesktop",      "mac": "AyuGram"},
    "64Gram":           {"win": "64Gram",           "linux": "64Gram",            "mac": "64Gram"},
    "Kotatogram":       {"win": "Kotatogram",       "linux": "Kotatogram",        "mac": "Kotatogram"},
}

# Firefox-подобные: базовые пути профилей по ОС
GECKO_BROWSERS = {
    "Mozilla Firefox":  {"win": "Mozilla/Firefox",  "linux": "mozilla/firefox"},
    "Thunderbird":      {"win": "Thunderbird",       "linux": "thunderbird"},
    "Waterfox":         {"win": "Waterfox",           "linux": "waterfox"},
    "LibreWolf":        {"win": "LibreWolf",          "linux": "librewolf"},
}

# Популярные сервисы: чем критичнее, тем важнее сменить пароль первым делом
TOP_SITES = {
    # почта - ключ ко всем сбросам паролей
    "mail.google.com": "gmail.com", "accounts.google.com": "gmail.com", "gmail.com": "gmail.com",
    "outlook.com": "outlook.com", "login.live.com": "outlook.com", "live.com": "outlook.com",
    "mail.yandex.ru": "yandex.ru", "yandex.ru": "yandex.ru", "passport.yandex.ru": "yandex.ru",
    "mail.ru": "mail.ru",
    "icloud.com": "icloud.com", "appleid.apple.com": "icloud.com",
    "proton.me": "proton.me", "protonmail.com": "proton.me",
    # крипта и деньги
    "binance.com": "binance.com", "bybit.com": "bybit.com", "okx.com": "okx.com",
    "coinbase.com": "coinbase.com", "kraken.com": "kraken.com", "htx.com": "htx.com",
    "gate.io": "gate.io", "mexc.com": "mexc.com", "bitget.com": "bitget.com",
    "payeer.com": "payyer.com", "bestchange.ru": "bestchange.ru",
    # банки/платежи
    "sberbank.ru": "sberbank.ru", "tinkoff.ru": "tinkoff.ru", "alfabank.ru": "alfabank.ru",
    "gosuslugi.ru": "gosuslugi.ru", "paypal.com": "paypal.com", "wise.com": "wise.com",
    # соцсети и мессенджеры
    "vk.com": "vk.com", "ok.ru": "ok.ru", "instagram.com": "instagram.com",
    "facebook.com": "facebook.com", "x.com": "x.com", "twitter.com": "x.com",
    "discord.com": "discord.com", "reddit.com": "reddit.com", "tiktok.com": "tiktok.com",
    "web.telegram.org": "telegram.org", "telegram.org": "telegram.org",
    # разработка и доступ
    "github.com": "github.com", "gitlab.com": "gitlab.com",
    "steamcommunity.com": "steam", "store.steampowered.com": "steam",
    "dropbox.com": "dropbox.com", "notion.so": "notion.so", "openai.com": "openai.com",
    "claude.ai": "claude.ai", "huggingface.co": "huggingface.co",
}


def mark_top(domains: list) -> dict:
    """Для списка доменов возвращает {domain: (is_top, canonical_name)}."""
    out = {}
    for d in domains:
        dl = d.lower().lstrip(".")
        hit = None
        for tkey, tname in TOP_SITES.items():
            if dl == tkey or dl.endswith("." + tkey):
                hit = tname
                break
        out[d] = (hit is not None, hit or "")
    return out

# Кошельки-расширения, которые стиллеры ищут в браузерах (chromium id)
WALLET_EXTENSIONS = {
    "MetaMask": "nkbihfbeogaeaoehlefnkodbefgpgknn",
    "Phantom": "bfnaelmomeimhlpmgjnjophhpkkoljpa",
    "Coinbase Wallet": "hnfanknocpekmmjcdhhjkcjjcfancbph",
    "Binance Wallet": "fhbohimaelbohpjbbldc Ookgkcljngpnb".replace("Oo", "oo").replace(" ", ""),
    "TronLink": "ibnejdfjmmknnfjahiofniklabhncdoh",
    "Rabby Wallet": "acamacbajcggaodcgnhngelbkahhofe",
    "Keplr": "dmkamcknogkgcdfhhbfdcphchnnepcij",
    "Solflare": "bhhhlkpacoghkmnpkgnkngbhnjdlhdhmljgp",
    "Ronin Wallet": "ejbalcboplbbahnjdpbplccmbhlpkcpe",
    "Exodus Web3": "aholpfdiajgnhifmjdlodbffgkndkcmi",
    "OKX Wallet": "mcohilncbfahbmgdjkbpemcciiolgcge",
    "Trust Wallet": "egjidjbpgiahmhokjpcmiemejkgjongh",
    "Bitget Wallet": "jiidiaalihmmhffjmplcadgpfjdbakkb",
    "Klip Wallet": "labcacgihbcbniikhnpaibdbnjnocho",
    "Martian (Aptos)": "enkdeimiiagfmkjgbhmdbkmcbkgdagf",
    "Petra (Aptos)": "ejjbalcboplbbahnjdpbplccmbhlpkcpe",
    "XDEFI": "hmeopcnnmnibbnfinkdhiejfcmbeabjm",
    "Zerion": "kdfjkmeeikakgmkcaofndphfnmlibodpocb",
}

# Имена кошельков для поиска в firefox-расширениях (по имени addon / имени xpi)
WALLET_NAME_HINTS = [
    "metamask", "phantom", "coinbase wallet", "binance wallet", "tronlink",
    "rabby", "keplr", "solflare", "ronin wallet", "exodus", "okx wallet",
    "trust wallet", "bitget wallet", "klip wallet", "martian", "petra",
    "xdefi", "zerion", "wallet connect", "myetherwallet", "math wallet",
    "jaxx liberty", "frame", "stakedwallet", "tonkeeper",
]


def local_appdata() -> str:
    if platform.system() == "Windows":
        return os.path.join(os.environ.get("LOCALAPPDATA", ""), "")
    return os.path.expanduser("~/.var/app")  # flatpak-стиль на linux не проверяем глубоко


def appdata() -> str:
    if platform.system() == "Windows":
        return os.environ.get("APPDATA", "")
    if platform.system() == "Darwin":
        return os.path.expanduser("~/Library/Application Support")
    return os.path.expanduser("~/.config")


def os_key() -> str:
    return {"Windows": "win", "Darwin": "mac", "Linux": "linux"}[platform.system()]


def chromium_user_data(rel: dict) -> str:
    """Путь к User Data для chromium-браузера на текущей ОС."""
    sysname = platform.system()
    rel_path = rel.get(os_key())
    if not rel_path:
        return ""
    if sysname == "Windows":
        return os.path.join(os.environ.get("LOCALAPPDATA", ""), rel_path, "User Data")
    if sysname == "Darwin":
        return os.path.join(os.path.expanduser("~/Library/Application Support"), rel_path, "User Data")
    # linux: у большинства ~/.config/<browser> уже есть Default/ без папки User Data,
    # но некоторые пакуют в User Data - проверяем оба варианта
    p = os.path.join(os.path.expanduser("~/.config"), rel_path)
    if os.path.isdir(os.path.join(p, "User Data")):
        return os.path.join(p, "User Data")
    return p


def client_base(rel: dict, win_base="appdata", linux_base="config", mac_base="appsupport") -> str:
    """Базовая директория данных клиента по ОС."""
    sysname = platform.system()
    rel_path = rel.get(os_key())
    if not rel_path:
        return ""
    if sysname == "Windows":
        base = os.environ.get("APPDATA", "") if win_base == "appdata" else os.environ.get("LOCALAPPDATA", "")
        return os.path.join(base, rel_path)
    if sysname == "Darwin":
        base = os.path.expanduser("~/Library/Application Support") if mac_base == "appsupport" \
            else os.path.expanduser("~/Library")
        return os.path.join(base, rel_path)
    return os.path.join(os.path.expanduser(f"~/.{linux_base}"), rel_path)


def chromium_profiles(user_data: str):
    """Возвращает список профилей Chromium (Default, Profile 1, ...)."""
    if not os.path.isdir(user_data):
        return []
    profs = []
    for entry in os.listdir(user_data):
        p = os.path.join(user_data, entry)
        if os.path.isdir(p) and (entry == "Default" or entry.startswith("Profile ")):
            profs.append(p)
    return profs or ([os.path.join(user_data, "Default")] if os.path.isdir(os.path.join(user_data, "Default")) else [])


def sqlite_count(db_path: str, query: str) -> tuple:
    """Открывает SQLite (копию не делаем - читаем read-only), возвращает (count, sample)."""
    if not os.path.isfile(db_path):
        return (0, [])
    try:
        con = sqlite3.connect(f"file:{db_path}?mode=ro&immutable=1", uri=True, timeout=3)
        cur = con.execute(query)
        rows = cur.fetchall()
        con.close()
        return (len(rows), rows)
    except Exception:
        # файл может быть залочен браузером - копируем во временную папку
        import tempfile, shutil
        tmp = os.path.join(tempfile.gettempdir(), f"wis_{int(time.time()*1000)}.db")
        try:
            shutil.copy2(db_path, tmp)
            con = sqlite3.connect(f"file:{tmp}?mode=ro", uri=True, timeout=3)
            cur = con.execute(query)
            rows = cur.fetchall()
            con.close()
            return (len(rows), rows)
        except Exception:
            return (0, [])
        finally:
            try:
                os.remove(tmp)
            except Exception:
                pass


def format_domain_list(domains: dict) -> list:
    """Форматирует {домен: количество}: топ-сайты первым блоком с выделением, потом остальные."""
    marks = mark_top(domains.keys())
    top_items = [(d, c) for d, c in sorted(domains.items(), key=lambda x: -x[1]) if marks[d][0]]
    rest_items = [(d, c) for d, c in sorted(domains.items(), key=lambda x: -x[1]) if not marks[d][0]]
    out = []
    if top_items:
        out.append(">>> МЕНЯТЬ ПЕРВЫМИ <<<")
        for d, c in top_items:
            name = marks[d][1]
            label = f"{d}" if name == d else f"{d} ({name})"
            out.append(f"  ** {label}: {c}")
    if rest_items:
        out.append("остальные:")
        for d, c in rest_items:
            out.append(f"  - {d}: {c}")
    return out


def scan_chromium_browser(name: str, user_data: str) -> list:
    findings = []
    profiles = chromium_profiles(user_data)
    if not profiles:
        return []
    details = []
    total_pw, total_cookies, total_cards, domains = 0, 0, 0, set()
    autofill_kinds = set()
    pw_domains = {}
    cookie_domains = {}
    for prof in profiles:
        # Пароли: Login Data -> logins (origin_url, username_value)
        n, rows = sqlite_count(os.path.join(prof, "Login Data"),
                               "SELECT origin_url, username_value FROM logins")
        for url, _user in rows:
            d = domain_of(url or "")
            if d:
                pw_domains.setdefault(d, 0)
                pw_domains[d] += 1
        total_pw += n
        domains.update(pw_domains.keys())

        # Cookies (значения НЕ читаем, только домены/счётчик)
        n, rows = sqlite_count(os.path.join(prof, "Network", "Cookies"),
                               "SELECT host_key FROM cookies")
        if n == 0:
            n, rows = sqlite_count(os.path.join(prof, "Cookies"),
                                   "SELECT host_key FROM cookies")
        total_cookies += n
        for h, in rows:
            if h:
                d = domain_of(h)
                cookie_domains[d] = cookie_domains.get(d, 0) + 1

        # Автозаполнение: Web Data -> autofill / credit_cards
        n, rows = sqlite_count(os.path.join(prof, "Web Data"),
                               "SELECT name FROM autofill")
        if n:
            total_cards += 0
            names = {r[0].lower() for r in rows}
            if names & {"cc-name", "cc-number", "cc-csc", "cc-exp"}:
                autofill_kinds.add("данные банковских карт")
            if any("address" in x or "zip" in x or "street" in x for x in names):
                autofill_kinds.add("адрес")
            if any("phone" in x or "tel" in x for x in names):
                autofill_kinds.add("телефон")
            if any("email" in x for x in names):
                autofill_kinds.add("email")
            details.append(f"автозаполнение: {n} записей ({', '.join(sorted(autofill_kinds)) or 'прочее'})")
        n, rows = sqlite_count(os.path.join(prof, "Web Data"),
                               "SELECT card_number_encrypted FROM credit_cards")
        if n:
            autofill_kinds.add("данные банковских карт")
            details.append(f"сохранённых банковских карт: {n} (номера шифрованы, но вор их расшифровал)")

    if total_pw:
        pw_details = format_domain_list(pw_domains)
        f = Finding("Браузеры", f"{name}: сохранённые пароли", SEVERITY_HIGH,
                    details=pw_details,
                    evidence=user_data, count=total_pw)
        findings.append(f)
    if total_cookies:
        ck_details = [f"всего cookies: {total_cookies}, доменов: {len(cookie_domains)}"]
        ck_details += format_domain_list(cookie_domains)
        ck_details.append("эти сессии надо завершить (выйти из аккаунтов на всех устройствах)")
        findings.append(Finding("Браузеры", f"{name}: cookies и сессии", SEVERITY_HIGH,
                                details=ck_details, evidence=user_data, count=total_cookies))
    if autofill_kinds:
        findings.append(Finding("Браузеры", f"{name}: автозаполнение",
                                SEVERITY_MEDIUM,
                                details=[d for d in details if "автозаполн" in d or "карт" in d],
                                evidence=user_data))

    # Кошельки-расширения
    for prof in profiles:
        exts_dir = os.path.join(prof, "Extensions")
        if not os.path.isdir(exts_dir):
            continue
        found = []
        for ext_id in os.listdir(exts_dir):
            for wname, wid in WALLET_EXTENSIONS.items():
                if wid and ext_id == wid:
                    found.append(wname)
        # fallback: ищем manifest.json с "ethereum"/"solana" permissions
        for ext_id in os.listdir(exts_dir):
            mf = os.path.join(exts_dir, ext_id, "*", "manifest.json")
            for m in glob.glob(mf):
                try:
                    txt = open(m, encoding="utf-8", errors="ignore").read(4000)
                    if any(k in txt for k in ("ethereum", "solana", "tronweb")):
                        name_hint = ""
                        import re
                        mm = re.search(r'"name"\s*:\s*"([^"]+)"', txt)
                        if mm:
                            name_hint = mm.group(1)
                        if name_hint and name_hint not in found:
                            found.append(name_hint)
                except Exception:
                    pass
        if found:
            findings.append(Finding("Криптокошельки",
                                    f"{name}: расширения-кошельки",
                                    SEVERITY_CRITICAL,
                                    details=[f"{w} - seed-фраза/приватные ключи были доступны вору" for w in found],
                                    evidence=exts_dir))
    return findings


def gecko_profiles_root(rel: dict) -> str:
    """Базовая папка профилей Firefox-семейства по ОС."""
    sysname = platform.system()
    rel_path = rel.get(os_key())
    if not rel_path:
        return ""
    if sysname == "Windows":
        return os.path.join(os.environ.get("APPDATA", ""), rel_path, "Profiles")
    if sysname == "Darwin":
        return os.path.join(os.path.expanduser("~/Library/Application Support"), rel_path)
    home = os.path.expanduser("~")
    candidates = [
        os.path.join(home, "." + rel_path),                      # ~/.mozilla/firefox
        os.path.join(home, ".var/app/org.mozilla.firefox/." + rel_path),  # flatpak
        os.path.join(home, "snap/firefox/common/." + rel_path),   # snap
        os.path.join(home, ".config", rel_path),                  # редкие сборки
    ]
    for c in candidates:
        if os.path.isdir(c):
            return c
    return candidates[0]


def scan_firefox_wallet_exts(profiles_root: str) -> list:
    """Кошельки-расширения в firefox: парсим extensions.json (default name) и xpi-файлы."""
    found = set()
    if not os.path.isdir(profiles_root):
        return []
    for prof in os.listdir(profiles_root):
        p = os.path.join(profiles_root, prof)
        if not os.path.isdir(p):
            continue
        # extensions.json - основной реестр дополнений
        ej = os.path.join(p, "extensions.json")
        if os.path.isfile(ej):
            try:
                data = json.load(open(ej, encoding="utf-8", errors="ignore"))
                for addon in data.get("addons", []):
                    aname = (addon.get("defaultLocale", {}).get("name") or addon.get("name") or "").lower()
                    if any(h in aname for h in WALLET_NAME_HINTS):
                        found.add(aname.strip().title())
            except Exception:
                pass
        # fallback: xpi-файлы в extensions/
        for xpi in walk_bounded(os.path.join(p, "extensions"), max_depth=1, patterns=[".xpi"]) \
                + walk_bounded(p, max_depth=1, patterns=[".xpi"]):
            base = os.path.basename(xpi).lower()
            if any(h.replace(" ", "") in base.replace(" ", "").replace("_", "") for h in WALLET_NAME_HINTS):
                found.add(os.path.basename(xpi))
    if found:
        return [Finding("Криптокошельки", "Firefox: расширения-кошельки",
                        SEVERITY_CRITICAL,
                        [f"{w} - seed-фраза/приватные ключи были доступны вору" for w in sorted(found)],
                        evidence=profiles_root)]
    return []


def scan_gecko_browser(name: str, profiles_root: str) -> list:
    findings = []
    if not os.path.isdir(profiles_root):
        return []
    total_pw, total_cookies = 0, 0
    details = []
    hosts = {}
    cookie_domains = {}
    for prof in os.listdir(profiles_root):
        p = os.path.join(profiles_root, prof)
        if not os.path.isdir(p):
            continue
        # logins.json содержит пароли (json), key4.db - ключ. Читаем только счётчик логинов.
        lj = os.path.join(p, "logins.json")
        if os.path.isfile(lj):
            try:
                data = json.load(open(lj, encoding="utf-8", errors="ignore"))
                logins = data.get("logins", [])
                total_pw += len(logins)
                for l in logins:
                    d = domain_of(l.get("hostname", ""))
                    hosts[d] = hosts.get(d, 0) + 1
            except Exception:
                pass
        cp = os.path.join(p, "cookies.sqlite")
        if os.path.isfile(cp):
            n, rows = sqlite_count(cp, "SELECT host FROM moz_cookies")
            total_cookies += n
            for h, in rows:
                if h:
                    d = domain_of(h)
                    cookie_domains[d] = cookie_domains.get(d, 0) + 1
    if total_pw:
        pw_details = format_domain_list(hosts)
        findings.append(Finding("Браузеры", f"{name}: сохранённые пароли",
                                SEVERITY_HIGH, pw_details, evidence=profiles_root, count=total_pw))
    if total_cookies:
        ck_details = [f"всего cookies: {total_cookies}, доменов: {len(cookie_domains)}"]
        ck_details += format_domain_list(cookie_domains)
        ck_details.append("эти сессии надо завершить (выйти из аккаунтов на всех устройствах)")
        findings.append(Finding("Браузеры", f"{name}: cookies и сессии",
                                SEVERITY_HIGH, details=ck_details, count=total_cookies))
    return findings


# ══════════════════════════ КРИПТОКОШЕЛЬКИ (десктоп) ══════════════════════════

DESKTOP_WALLETS = {
    # имя: (severity, что вор забирает)
    "Exodus": ("exodus", SEVERITY_CRITICAL, "файлы кошелька (seed-фраза восстанавливается)"),
    "Electrum": ("electrum/wallets", SEVERITY_CRITICAL, "файлы кошелька (*.wallet - приватные ключи)"),
    "Atomic Wallet": ("atomic", SEVERITY_CRITICAL, "локальное хранилище кошелька"),
    "Coinomi": ("Coinomi/Coinomi/wallets", SEVERITY_CRITICAL, "файлы кошелька"),
    "Binance": ("Binance", SEVERITY_HIGH, "токен сессии приложения"),
    "Bitcoin Core": (".bitcoin/wallet", SEVERITY_CRITICAL, "wallet.dat (приватные ключи)"),
    "Daedalus": ("Daedalus Mainnet", SEVERITY_CRITICAL, "файлы кошелька"),
    "Wasabi": ("WasabiWallet/Wallets", SEVERITY_CRITICAL, "файлы кошелька"),
    "Ethereum Wallet (Mist)": ("Ethereum/keystore", SEVERITY_CRITICAL, "keystore-файлы"),
    "Jaxx": (".jaxx", SEVERITY_CRITICAL, "локальное хранилище"),
    "Guarda": ("Guarda", SEVERITY_HIGH, "локальное хранилище"),
    "MyCrypto": ("MyCrypto", SEVERITY_HIGH, "локальное хранилище"),
    "TronLink Desktop": ("TronLink", SEVERITY_HIGH, "хранилище"),
}


def scan_desktop_wallets() -> list:
    findings = []
    bases = []
    sysname = platform.system()
    if sysname == "Windows":
        bases = [os.environ.get("APPDATA", ""), os.environ.get("LOCALAPPDATA", "")]
    elif sysname == "Darwin":
        bases = [os.path.expanduser("~/Library/Application Support"), os.path.expanduser("~")]
    else:
        bases = [os.path.expanduser("~/.config"), os.path.expanduser("~")]

    for wname, (rel, sev, what) in DESKTOP_WALLETS.items():
        for base in bases:
            if not base:
                continue
            path = os.path.join(base, rel)
            if os.path.isdir(path):
                files = []
                for root, _dirs, fs in os.walk(path):
                    for fn in fs:
                        files.append(os.path.relpath(os.path.join(root, fn), path))
                    if len(files) > 40:
                        break
                interesting = [f for f in files if any(
                    k in f.lower() for k in ("wallet", "seed", "key", "keystore", "info"))]
                det = [f"директория кошелька найдена: {len(files)} файлов"
                       + (f", из них {len(interesting)} похожи на хранилища ключей" if interesting else ""),
                       f"вор копирует всё целиком: {what}"]
                findings.append(Finding("Криптокошельки", f"{wname}", sev, det, evidence=path))
                break
    return findings


# ══════════════════════════ МЕССЕНДЖЕРЫ / ИГРЫ ══════════════════════════

def _scan_discord_dir(name: str, base: str) -> list:
    if not base or not os.path.isdir(base):
        return []
    tok_files = []
    for root, _d, fs in os.walk(base):
        if root.count(os.sep) - base.count(os.sep) > 4:
            continue
        for fn in fs:
            if fn.endswith(".ldb") and "Local Storage" in root:
                tok_files.append(os.path.join(root, fn))
    if tok_files:
        return [Finding("Мессенджеры", f"{name}: токен сессии",
                        SEVERITY_HIGH,
                        [f"найдены файлы локального хранилища {name} ({len(tok_files)})",
                         "токен даёт полный доступ к аккаунту без пароля",
                         "вор мог читать ваши личные сообщения и писать от вашего имени"],
                        evidence=base)]
    return []


def scan_discord() -> list:
    findings = []
    for name, rel in DISCORD_CLIENTS.items():
        findings += _scan_discord_dir(name, client_base(rel))
    return findings


def scan_telegram() -> list:
    findings = []
    for name, rel in TELEGRAM_CLIENTS.items():
        # win: %APPDATA%/<name>/tdata | linux: ~/.local/share/<name>/tdata | mac: ~/Library/Application Support/<name>/tdata
        sysname = platform.system()
        rel_path = rel.get(os_key())
        if not rel_path:
            continue
        if sysname == "Windows":
            base = os.path.join(os.environ.get("APPDATA", ""), rel_path, "tdata")
        elif sysname == "Darwin":
            base = os.path.expanduser(f"~/Library/Application Support/{rel_path}/tdata")
        else:
            share = os.path.expanduser("~/.local/share")
            base = None
            # регистронезависимый поиск: AyuGram может быть ayugram/AyuGram
            if os.path.isdir(share):
                for entry in os.listdir(share):
                    if entry.lower() == rel_path.lower():
                        base = os.path.join(share, entry, "tdata")
                        break
            # fallback: ищем tdata глубже (~/.local/share/<что-угодно>/<client>/tdata)
            if (base is None or not os.path.isdir(base)) and os.path.isdir(share):
                for entry in os.listdir(share):
                    sub = os.path.join(share, entry)
                    if not os.path.isdir(sub):
                        continue
                    for entry2 in os.listdir(sub):
                        if entry2.lower() == rel_path.lower():
                            b2 = os.path.join(sub, entry2, "tdata")
                            if os.path.isdir(b2):
                                base = b2
                                break
                    if base and os.path.isdir(base):
                        break
            if base is None:
                base = os.path.join(share, rel_path, "tdata")
        if os.path.isdir(base) and os.path.isfile(os.path.join(base, "key_datas")):
            findings.append(Finding("Мессенджеры", f"{name}: сессия (tdata)",
                                    SEVERITY_HIGH,
                                    [f"найдена локальная сессия {name} (tdata)",
                                     "с ней вор заходит в аккаунт с чужого устройства, коды не требуются",
                                     "рекомендация: Settings > Devices > завершить все сторонние сессии"],
                                    evidence=os.path.dirname(base)))
    return findings


def scan_steam() -> list:
    findings = []
    base = None
    sysname = platform.system()
    if sysname == "Windows":
        base = os.path.join(os.environ.get("APPDATA", ""), "..", "Local", "Steam")
    if base and os.path.isdir(base):
        ssfn = glob.glob(os.path.join(base, "ssfn*"))
        if ssfn:
            findings.append(Finding("Игры", "Steam: файлы авторизации (ssfn)",
                                    SEVERITY_MEDIUM,
                                    [f"найдено {len(ssfn)} ssfn-файлов",
                                     "вор мог получить доступ к аккаунту Steam (в т.ч. инвентарь, баланс)"],
                                    evidence=base))
    # loginusers.vdf
    steam_root = os.path.expanduser("~/.steam/steam/config/loginusers.vdf")
    if not os.path.isfile(steam_root) and platform.system() == "Windows":
        for d in ("C:/Program Files (x86)/Steam", "C:/Steam"):
            p = os.path.join(d, "config", "loginusers.vdf")
            if os.path.isfile(p):
                steam_root = p
                break
    if os.path.isfile(steam_root):
        try:
            names = [l.split('"')[1] for l in open(steam_root, encoding="utf-8", errors="ignore")
                     if '"AccountName"' in l]
            findings.append(Finding("Игры", "Steam: аккаунт",
                                    SEVERITY_MEDIUM,
                                    [f"сохранён логин аккаунта Steam: {mask_login(', '.join(names)) if names else 'да'}"],
                                    evidence=steam_root))
        except Exception:
            pass
    return findings


# Игровые платформы: пути к данным аккаунтов (стиллеры тащат сессии/токены)
GAME_PLATFORMS = {
    "Battle.net":       {"win": ["Battle.net"],                        "mac": ["Battle.net"],  "linux": ["battle.net"]},
    "Epic Games":       {"win": ["EpicGamesLauncher", "Epic Games"],   "mac": ["Epic Games"],  "linux": ["epic games", "epicgameslauncher"]},
    "Riot Client":      {"win": ["Riot Client", "Riot Games"],         "mac": ["Riot Games"],  "linux": ["riot client", "riot games"]},
    "EA app / Origin":  {"win": ["Electronic Arts/EA app", "Origin"],  "mac": ["Origin"],      "linux": ["origin", "ea app"]},
    "Ubisoft Connect":  {"win": ["Ubisoft/Ubisoft Game Launcher", "Ubisoft Game Launcher"], "mac": ["Ubisoft"], "linux": ["ubisoft connect", "ubisoft game launcher"]},
    "GOG Galaxy":       {"win": ["GOG.com"],                           "mac": ["GOG.com"],     "linux": ["gog", "gog galaxy"]},
}


def scan_game_platforms() -> list:
    """Сессии игровых лаунчеров: вор получает доступ к аккаунту (библиотека, баланс, инвентарь)."""
    findings = []
    sysname = platform.system()
    for name, rel in GAME_PLATFORMS.items():
        rel_paths = rel.get(os_key())
        if not rel_paths:
            continue
        for rel_path in rel_paths:
            candidates = []
            if sysname == "Windows":
                for env in ("APPDATA", "LOCALAPPDATA"):
                    if os.environ.get(env):
                        candidates.append(os.path.join(os.environ[env], rel_path))
                candidates.append(os.path.join(os.environ.get("PROGRAMDATA", "C:/ProgramData"), rel_path))
            elif sysname == "Darwin":
                candidates.append(os.path.join(os.path.expanduser("~/Library/Application Support"), rel_path))
            else:
                home = os.path.expanduser("~")
                candidates += [
                    os.path.join(home, ".config", rel_path.lower()),
                    os.path.join(home, ".local/share", rel_path.lower()),
                    os.path.join(home, ".var", "com." + rel_path.split("/")[0].lower(), "config"),
                ]
            hit = next((c for c in candidates if os.path.isdir(c)), None)
            if hit:
                # ищем маркеры сессий/аккаунтов в первых двух уровнях
                markers = []
                for dp, dirs, fs in os.walk(hit):
                    if dp.count(os.sep) - hit.count(os.sep) >= 2:
                        dirs[:] = []
                        continue
                    for fn in fs:
                        low = fn.lower()
                        if any(k in low for k in ("account", "sso", "session", "login", "token", "cache", "config")):
                            markers.append(fn)
                    if len(markers) > 8:
                        break
                det = ["найдены данные аккаунта лаунчера",
                       "вор получает доступ к аккаунту: библиотека игр, баланс, инвентарь, привязки"]
                if markers:
                    det.append("файлы-маркеры: " + ", ".join(sorted(set(markers))[:6]))
                findings.append(Finding("Игры", f"{name}: аккаунт лаунчера",
                                        SEVERITY_HIGH, det, evidence=hit))
                break
    return findings


# ══════════════════════════ SSH / GPG / RDP / KeePass ══════════════════════════

def scan_ssh_gpg() -> list:
    findings = []
    ssh_dir = os.path.expanduser("~/.ssh")
    if os.path.isdir(ssh_dir):
        keys = [f for f in os.listdir(ssh_dir)
                if not f.endswith(".pub") and f.startswith(("id_", "ssh_", "deploy"))]
        if keys:
            findings.append(Finding("Ключи и доступ", "SSH-ключи",
                                    SEVERITY_HIGH,
                                    [f"найдено приватных ключей: {len(keys)} ({', '.join(keys[:5])})",
                                     "вор мог подключаться к вашим серверам без пароля"],
                                    evidence=ssh_dir))
    gpg_dir = os.path.expanduser("~/.gnupg")
    if platform.system() == "Windows":
        gpg_dir = os.path.join(os.environ.get("APPDATA", ""), "gnupg")
    if os.path.isdir(gpg_dir):
        sec = [f for f in os.listdir(gpg_dir) if "private-keys" in f]
        if sec or os.path.isfile(os.path.join(gpg_dir, "secring.gpg")):
            findings.append(Finding("Ключи и доступ", "GPG-ключи",
                                    SEVERITY_HIGH,
                                    ["найдено хранилище приватных GPG-ключей"],
                                    evidence=gpg_dir))
    # RDP файлы
    docs = os.path.expanduser("~/Documents")
    rdp = walk_bounded(docs, max_depth=3, patterns=[".rdp"]) if os.path.isdir(docs) else []
    if rdp:
        findings.append(Finding("Ключи и доступ", "RDP-подключения",
                                SEVERITY_MEDIUM,
                                [f"найдено {len(rdp)} .rdp файлов (могут содержать адреса серверов и логины)"],
                                evidence=docs))
    return findings


def scan_keepass() -> list:
    findings = []
    bases = [os.path.expanduser("~/Documents"), os.path.expanduser("~/Desktop")]
    found = []
    for b in bases:
        if not os.path.isdir(b):
            continue
        found += walk_bounded(b, max_depth=3, patterns=[".kdbx"])
        if len(found) > 10:
            break
    if found:
        findings.append(Finding("Пароль-менеджеры", "KeePass-базы",
                                SEVERITY_CRITICAL,
                                [f"найдено баз: {len(found)}",
                                 "вскрытие базы возможно по паролю из браузера, вор забирает файл целиком"],
                                evidence=os.path.dirname(found[0])))
    return findings


def scan_ftp_vpn() -> list:
    findings = []
    fz = os.path.join(appdata(), "FileZilla")
    if platform.system() == "Windows":
        fz = os.path.join(os.environ.get("APPDATA", ""), "FileZilla")
    if os.path.isdir(fz):
        rs = os.path.join(fz, "recentservers.xml") or os.path.join(fz, "sitemanager.xml")
        for fname in ("recentservers.xml", "sitemanager.xml"):
            p = os.path.join(fz, fname)
            if os.path.isfile(p):
                try:
                    import re
                    txt = open(p, encoding="utf-8", errors="ignore").read()
                    hosts = re.findall(r"<Host>([^<]+)</Host>", txt)
                    users = re.findall(r"<User>([^<]+)</User>", txt)
                    det = [f"сохранённых FTP/SSH-подключений: {len(hosts)}"]
                    if hosts:
                        det.append(f"серверы: {', '.join(hosts[:5])}")
                    if users:
                        det.append(f"логины (замаскированы): {', '.join(mask_login(u) for u in users[:5])}")
                    det.append("пароли хранятся в файле в открытом виде и были доступны вору")
                    findings.append(Finding("FTP и VPN", "FileZilla: сохранённые подключения",
                                            SEVERITY_HIGH, det, evidence=p))
                except Exception:
                    pass
                break
    # OpenVPN configs
    home = os.path.expanduser("~")
    ovpn = []
    for sub in ("Documents", "Desktop", "Downloads", "OpenVPN", "openvpn"):
        p = os.path.join(home, sub)
        if os.path.isdir(p):
            ovpn += walk_bounded(p, max_depth=2, patterns=[".ovpn"])
            break
    if platform.system() == "Windows":
        for d in ("OpenVPN/config", "OpenVPN"):
            p = os.path.join(os.environ.get("USERPROFILE", home), d)
            if os.path.isdir(p):
                ovpn += walk_bounded(p, max_depth=2, patterns=[".ovpn"])
    if ovpn:
        findings.append(Finding("FTP и VPN", "OpenVPN: конфигурации",
                                SEVERITY_MEDIUM,
                                [f"найдено {len(ovpn)} конфигов VPN (могут содержать логин/пароль)"]))
    return findings


# ══════════════════════════ ФАЙЛЫ ПО МАСКАМ ══════════════════════════

# классические маски стиллеров для сбора файлов
STEALER_FILE_MASKS = [
    "*password*", "*passwd*", "*login*", "*seed*", "*wallet*", "*backup*",
    "*2fa*", "*auth*", "*secret*", "*api*key*", "*token*", "*keyfile*",
    "*kэy*", "/*.txt",
]


def scan_sensitive_files() -> list:
    """Стиллеры копируют файлы с чувствительными именами из Документов/Рабочего стола.
    Показываем только пути - без содержимого."""
    findings = []
    scan_roots = []
    home = os.path.expanduser("~")
    for sub in ("Documents", "Desktop", "Downloads"):
        p = os.path.join(home, sub)
        if os.path.isdir(p):
            scan_roots.append(p)
    if platform.system() == "Windows":
        scan_roots.append(os.path.join(home, "OneDrive"))
    matches = []
    patterns = ["password", "passwd", "seed", "wallet", "2fa", "secret",
                "api_key", "apikey", "token", "backup_code", "private_key"]
    for root in scan_roots:
        matches += walk_bounded(root, max_depth=3, patterns=patterns)
    if matches:
        det = [f"файлов с чувствительными именами: {len(matches)}",
               "стиллер копирует такие файлы целиком (backup-коды, seed-фразы из txt и т.п.)"]
        det += [f"- {os.path.basename(m)} ({os.path.getsize(m)} байт)" for m in matches[:10]]
        findings.append(Finding("Файлы", "Документы с чувствительными именами",
                                SEVERITY_HIGH, det, evidence=os.path.dirname(matches[0])))
    return findings


# ══════════════════════════ СИСТЕМА ══════════════════════════

def scan_system_info() -> list:
    findings = []
    uname = platform.uname()
    details = [
        f"ОС: {uname.system} {uname.release}",
        f"имя компьютера: {uname.node}",
        f"пользователь: {mask_login(os.environ.get('USER') or os.environ.get('USERNAME') or '')}",
        "эта информация всегда попадает в лог стиллера (используется для продажи доступа)",
    ]
    findings.append(Finding("Системная информация", "Профиль системы",
                            SEVERITY_INFO, details))
    return findings


# ══════════════════════════ СБОРКА ══════════════════════════

def run_scan(verbose=False) -> list:
    steps = [
        ("системная информация", scan_system_info),
    ]
    sysname = platform.system()

    def _browsers():
        out = []
        for name, rel in CHROMIUM_BROWSERS.items():
            ud = chromium_user_data(rel)
            if ud and os.path.isdir(ud):
                if verbose:
                    print(f"  [скан] {name}...", file=sys.stderr, flush=True)
                out += scan_chromium_browser(name, ud)
        for name, rel in GECKO_BROWSERS.items():
            pr = gecko_profiles_root(rel)
            if pr and os.path.isdir(pr):
                if verbose:
                    print(f"  [скан] {name}...", file=sys.stderr, flush=True)
                out += scan_gecko_browser(name, pr)
                out += scan_firefox_wallet_exts(pr)
        return out

    steps += [
        ("браузеры", _browsers),
        ("криптокошельки", scan_desktop_wallets),
        ("мессенджеры (Discord, Telegram)", lambda: scan_discord() + scan_telegram()),
        ("Steam и игровые платформы", lambda: scan_steam() + scan_game_platforms()),
        ("ключи (SSH, GPG, RDP, KeePass)", lambda: scan_ssh_gpg() + scan_keepass()),
        ("FTP и VPN", scan_ftp_vpn),
        ("файлы с чувствительными именами", scan_sensitive_files),
    ]

    findings = []
    for label, fn in steps:
        if verbose:
            print(f"[{APP_NAME}] сканирую: {label}", file=sys.stderr, flush=True)
        try:
            findings += fn()
        except Exception as e:
            if verbose:
                print(f"  [!] ошибка на шаге '{label}': {e}", file=sys.stderr, flush=True)
    # сортировка: критичное сверху
    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.category))
    return findings


def recommendations(findings) -> list:
    recs = []
    cats = {f.category for f in findings}
    sevs = {f.severity for f in findings}
    if any(f.title.startswith(("Google Chrome", "Microsoft Edge", "Brave", "Opera"))
           and "пароли" in f.title for f in findings) or \
       any("парол" in f.title for f in findings):
        recs.append("Смените пароли главных аккаунтов (почта - первым делом) с ДРУГОГО чистого устройства. "
                    "Вор мог сохранить старые сессии - после смены пароля завершите все сессии вручную.")
    if any("cookies" in f.title or "сессии" in f.title for f in findings):
        recs.append("Выйдите из всех аккаунтов на всех устройствах (cookie-сессии живут своей жизнью "
                    "и не умирают от смены пароля в некоторых сервисах).")
    if "Криптокошельки" in cats:
        recs.append("КРИТИЧНО: создайте НОВЫЙ кошелёк на чистом устройстве, переведите туда все средства, "
                    "старый seed считайте скомпрометированным. Переводите с чистого ПК, не с заражённого.")
    if any("Discord" in f.title for f in findings):
        recs.append("Discord: смените пароль, включите 2FA, проверьте Settings > Authorized Apps "
                    "и вебхуки в ваших серверах.")
    if any("Telegram" in f.title for f in findings):
        recs.append("Telegram: Settings > Devices > Terminate all other sessions, затем включите облачный пароль.")
    if any("SSH" in f.title or "KeePass" in f.title for f in findings):
        recs.append("Замените SSH-ключи на серверах и смените мастер-пароль KeePass-базы, "
                    "файлы считаются скомпрометированными.")
    if any("FileZilla" in f.title for f in findings):
        recs.append("Смените пароли FTP/SSH-серверов, сохранённые в FileZilla - они были в открытом виде.")
    recs.append("Перед всеми сменами паролей: проверьте ПК антивирусом "
                "(KVRT, ESET Online Scanner) или переустановите систему, "
                "иначе вор прочитает и новые пароли.")
    recs.append("Включите 2FA везде, где ещё не включена.")
    return recs


# ══════════════════════════ CLI-ОТЧЁТ ══════════════════════════

SEV_LABEL = {SEVERITY_CRITICAL: "КРИТИЧНО",
             SEVERITY_HIGH: "ОПАСНО",
             SEVERITY_MEDIUM: "СРЕДНЕ",
             SEVERITY_INFO: "ИНФО"}


def build_text_report(findings, recs) -> str:
    lines = []
    lines.append("=" * 64)
    lines.append(f"  {APP_NAME} v{APP_VERSION} - отчёт о возможной утечке")
    lines.append(f"  {datetime.now().strftime('%Y-%m-%d %H:%M')}, {platform.node()}")
    lines.append("=" * 64)
    lines.append("")
    lines.append("Приложение показывает, какие данные стиллер МОГ украсть с этого")
    lines.append("ПК. Секретные значения не извлекаются и не показываются.")
    lines.append("")
    if not findings:
        lines.append("Ценных для стиллера данных не найдено. Повезло.")
    cur_cat = None
    for f in findings:
        if f.category != cur_cat:
            cur_cat = f.category
            lines.append("")
            lines.append(f"--- {cur_cat.upper()} ---")
        lines.append(f"[{SEV_LABEL[f.severity]}] {f.title}"
                     + (f"  ({f.count} записей)" if f.count else ""))
        for d in f.details:
            lines.append(f"    {d}")
    lines.append("")
    lines.append("=" * 64)
    lines.append("ЧТО ДЕЛАТЬ (в порядке приоритета):")
    lines.append("=" * 64)
    for i, r in enumerate(recs, 1):
        lines.append(f"{i}. {r}")
    lines.append("")
    lines.append("Этот отчёт безопасно показывать кому угодно - секретов в нём нет.")
    return "\n".join(lines)


def build_html_report(findings, recs) -> str:
    """Однофайловый красивый отчёт: inline CSS, ноль зависимостей."""

    def esc(s):
        return html.escape(str(s))

    def render_details(dets):
        """Детали находки: строки '>>> ...' = баннер, '** ' = приоритет, '- ' = прочее."""
        out = []
        in_priority = False
        for d in dets:
            d_esc = esc(d)
            if d.startswith(">>>"):
                out.append("<div class='prio-banner'>МЕНЯТЬ ПЕРВЫМИ</div>")
                in_priority = True
            elif d.startswith("  ** "):
                out.append(f"<div class='prio-item'>{'&#9888;'} {d_esc[5:]}</div>")
            elif d.startswith("остальные:"):
                in_priority = False
                out.append(f"<div class='dim-label'>{d_esc}</div>")
            elif d.startswith("  - "):
                out.append(f"<div class='det'>{d_esc[4:]}</div>")
            else:
                out.append(f"<div class='det'>{d_esc}</div>")
        return "".join(out)

    # сводка по severity
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "info": 0}
    for f in findings:
        sev_counts[f.severity] += 1

    # все приоритетные домены из всех браузеров -> сводный блок вверху
    prio_domains = []
    for f in findings:
        for d in f.details:
            if d.startswith("  ** "):
                prio_domains.append((f.category, d[5:].strip()))
    if prio_domains:
        prio_html = "".join(
            f"<div class='prio-item'>&#9888; <b>{esc(dom)}</b> <span class='dim'>({esc(cat)})</span></div>"
            for cat, dom in prio_domains)
        prio_block = f"""
<section class='prio'>
<h2>&#128680; Менять первыми</h2>
<p class='dim'>эти аккаунты воры используют в первую очередь (почта, крипта, банки, соцсети)</p>
{prio_html}
</section>"""
    else:
        prio_block = ""

    stats = f"""
<div class='stats'>
  <div class='stat s-critical'><div class='num'>{sev_counts['critical']}</div><div class='lbl'>критично</div></div>
  <div class='stat s-high'><div class='num'>{sev_counts['high']}</div><div class='lbl'>опасно</div></div>
  <div class='stat s-medium'><div class='num'>{sev_counts['medium']}</div><div class='lbl'>средне</div></div>
  <div class='stat s-info'><div class='num'>{sev_counts['info']}</div><div class='lbl'>инфо</div></div>
  <div class='stat s-total'><div class='num'>{len(findings)}</div><div class='lbl'>всего находок</div></div>
</div>"""

    # категории по порядку следования
    body = []
    cur_cat = None
    for f in findings:
        if f.category != cur_cat:
            cur_cat = f.category
            body.append(f"<h2>{esc(f.category)}</h2>")
        cnt = f" <span class='cnt'>{f.count} зап.</span>" if f.count else ""
        body.append(
            f"<div class='finding {f.severity}'>"
            f"<div class='f-head'><span class='badge b-{f.severity}'>{esc(SEV_LABEL[f.severity])}</span>"
            f"<b>{esc(f.title)}</b>{cnt}</div>"
            f"{render_details(f.details)}</div>")
    body_html = "".join(body)

    recs_html = "".join(
        f"<div class='rec'><b>{i}.</b> {esc(r)}</div>" for i, r in enumerate(recs, 1))

    return f"""<!DOCTYPE html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{APP_NAME} - отчёт</title>
<style>
:root {{
  --bg:#0d1117; --card:#161b22; --border:#30363d; --text:#e6edf3; --dim:#8b949e;
  --red:#f85149; --orange:#d29922; --yellow:#e3b341; --blue:#58a6ff; --green:#3fb950;
}}
*{{box-sizing:border-box}}
body{{font-family:-apple-system,'Segoe UI',Roboto,'Helvetica Neue',sans-serif;
background:var(--bg);color:var(--text);margin:0;padding:24px 16px;line-height:1.55}}
.wrap{{max-width:860px;margin:0 auto}}
h1{{font-size:1.6em;margin:0 0 4px}}
h2{{font-size:1.15em;margin:36px 0 12px;padding-bottom:6px;border-bottom:1px solid var(--border)}}
.dim{{color:var(--dim)}} .dim-label{{color:var(--dim);font-size:.85em;margin-top:8px}}
.stats{{display:flex;gap:10px;margin:20px 0;flex-wrap:wrap}}
.stat{{flex:1;min-width:110px;background:var(--card);border:1px solid var(--border);
border-radius:10px;padding:12px;text-align:center}}
.stat .num{{font-size:1.7em;font-weight:700}}
.s-critical .num{{color:var(--red)}} .s-high .num{{color:var(--orange)}}
.s-medium .num{{color:var(--yellow)}} .s-info .num{{color:var(--blue)}}
.s-total .num{{color:var(--text)}}
.stat .lbl{{font-size:.8em;color:var(--dim);text-transform:uppercase;letter-spacing:.05em}}
.prio{{background:#2d1114;border:2px solid var(--red);border-radius:12px;
padding:16px 20px;margin:24px 0}}
.prio h2{{margin:0 0 4px;border:none;color:var(--red)}}
.prio-banner{{background:var(--red);color:#fff;font-weight:700;text-align:center;
border-radius:6px;padding:4px;margin:8px 0;font-size:.85em;letter-spacing:.08em}}
.prio-item{{background:#3d1618;border-radius:6px;padding:8px 12px;margin:6px 0;
font-weight:600;color:#ffd8d3}}
.finding{{background:var(--card);border:1px solid var(--border);border-radius:10px;
padding:14px 18px;margin:12px 0}}
.critical{{border-left:4px solid var(--red)}} .high{{border-left:4px solid var(--orange)}}
.medium{{border-left:4px solid var(--yellow)}} .info{{border-left:4px solid var(--blue)}}
.f-head{{margin-bottom:8px}} .cnt{{color:var(--dim);font-weight:400;font-size:.85em}}
.badge{{font-weight:700;text-transform:uppercase;font-size:.72em;padding:2px 8px;
border-radius:4px;margin-right:8px;vertical-align:middle}}
.b-critical{{background:var(--red);color:#fff}} .b-high{{background:var(--orange);color:#fff}}
.b-medium{{background:var(--yellow);color:#111}} .b-info{{background:var(--blue);color:#fff}}
.det{{color:var(--dim);font-size:.92em;padding:1px 0 1px 12px;border-left:2px solid var(--border);margin:2px 0}}
.rec{{background:#11212e;border:1px solid #1f4460;border-radius:10px;
padding:12px 16px;margin:8px 0}}
.foot{{color:var(--dim);margin-top:36px;font-size:.85em;border-top:1px solid var(--border);padding-top:12px}}
</style></head><body><div class='wrap'>
<h1>{APP_NAME} <span class='dim' style='font-size:.6em'>v{APP_VERSION}</span></h1>
<p class='dim'>отчёт о том, какие данные стиллер мог украсть с этого ПК.
{datetime.now().strftime('%d.%m.%Y %H:%M')} - {esc(platform.node())}.
секретные значения (пароли, токены, seed-фразы) <b>не извлекались</b> - только факт их наличия.</p>
{stats}
{prio_block}
{body_html}
<h2>Что делать (по приоритету)</h2>
{recs_html}
<div class='foot'>этот отчёт безопасно показывать кому угодно - секретов в нём нет.<br>
{APP_NAME} работает полностью оффлайн, ничего не отправляет в сеть.</div>
</div></body></html>"""


# ══════════════════════════ GUI (tkinter) ══════════════════════════

def run_gui():
    import tkinter as tk
    from tkinter import ttk, filedialog

    root = tk.Tk()
    root.title(f"{APP_NAME} v{APP_VERSION}")
    root.geometry("900x640")
    root.configure(bg="#141414")

    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except Exception:
        pass
    bg, fg, sel = "#141414", "#eee", "#2a2a2a"
    for w in ("Treeview", "TLabel", "TButton", "TFrame"):
        try:
            style.configure(w, background=bg, foreground=fg, fieldbackground=bg)
        except Exception:
            pass
    style.configure("Treeview", rowheight=26, font=("TkDefaultFont", 10))

    header = tk.Label(root, text=f"{APP_NAME} v{APP_VERSION}",
                      font=("TkDefaultFont", 16, "bold"), bg=bg, fg=fg)
    header.pack(pady=8)
    sub = tk.Label(root, text="что стиллер мог украсть с этого ПК (секреты замаскированы)",
                   bg=bg, fg="#888")
    sub.pack()

    toolbar = tk.Frame(root, bg=bg)
    toolbar.pack(fill="x", pady=6)

    # шрифт с поддержкой эмодзи-символов не нужен - используем текст
    cols = ("sev", "title", "count")
    tree = ttk.Treeview(root, columns=cols, show="tree headings")
    tree.heading("#0", text="Категория / находка")
    tree.heading("sev", text="Уровень")
    tree.heading("title", text="Детали")
    tree.heading("count", text="Записей")
    tree.column("#0", width=260)
    tree.column("sev", width=90)
    tree.column("title", width=420)
    tree.column("count", width=70, anchor="e")
    tree.pack(fill="both", expand=True, padx=12, pady=(2, 6))

    status = tk.Label(root, text="готов к сканированию", bg=bg, fg="#888")
    status.pack(pady=4)

    report_data = {"findings": [], "recs": []}

    sev_tag_color = {"critical": "#e74c3c", "high": "#e67e22",
                     "medium": "#f1c40f", "info": "#3498db"}

    def do_scan():
        tree.delete(*tree.get_children())
        status.config(text="сканирую... (браузеры, кошельки, мессенджеры, ключи)")
        root.update_idletasks()
        t0 = time.time()
        findings = run_scan()
        recs = recommendations(findings)
        report_data["findings"], report_data["recs"] = findings, recs
        cur_cat = None
        cat_item = None
        for f in findings:
            if f.category != cur_cat:
                cur_cat = f.category
                cat_item = tree.insert("", "end", text=f.category.upper(), open=True,
                                       values=("", "", ""))
            dets = " | ".join(f.details[:3])
            tree.insert(cat_item, "end", text=f"  {f.title}",
                        values=(SEV_LABEL[f.severity], dets, f.count or ""),
                        tags=(f.severity,))
        for sev, color in sev_tag_color.items():
            tree.tag_configure(sev, foreground=color)
        sev_summary = {}
        for f in findings:
            sev_summary[f.severity] = sev_summary.get(f.severity, 0) + 1
        summary = ", ".join(f"{SEV_LABEL[k]}: {v}" for k, v in
                            sorted(sev_summary.items(), key=lambda x: SEVERITY_ORDER.get(x[0], 9)))
        status.config(text=f"готово за {time.time()-t0:.1f}с  |  {summary or 'цельного не найдено'}")

    def show_recs():
        if not report_data["findings"]:
            do_scan()
        win = tk.Toplevel(root)
        win.title("Что делать")
        win.configure(bg=bg)
        txt = tk.Text(win, wrap="word", bg=bg, fg=fg, width=80, height=28,
                      padx=10, pady=10, relief="flat")
        txt.insert("1.0", "ЧТО ДЕЛАТЬ (по приоритету):\n\n")
        for i, r in enumerate(report_data["recs"], 1):
            txt.insert("end", f"{i}. {r}\n\n")
        txt.config(state="disabled")
        txt.pack()

    def export_html():
        if not report_data["findings"]:
            do_scan()
        path = filedialog.asksaveasfilename(defaultextension=".html",
                                            initialfile=f"whatitsteals_{int(time.time())}.html",
                                            filetypes=[("HTML", "*.html")])
        if path:
            open(path, "w", encoding="utf-8").write(
                build_html_report(report_data["findings"], report_data["recs"]))
            status.config(text=f"отчёт сохранён: {path}")

    def export_txt():
        if not report_data["findings"]:
            do_scan()
        path = filedialog.asksaveasfilename(defaultextension=".txt",
                                            initialfile=f"whatitsteals_{int(time.time())}.txt",
                                            filetypes=[("Text", "*.txt")])
        if path:
            open(path, "w", encoding="utf-8").write(
                build_text_report(report_data["findings"], report_data["recs"]))
            status.config(text=f"отчёт сохранён: {path}")

    for text, cmd in (("Сканировать", do_scan), ("Рекомендации", show_recs),
                     ("Экспорт HTML", export_html), ("Экспорт TXT", export_txt)):
        tk.Button(toolbar, text=text, command=cmd, bg="#2a2a2a", fg=fg,
                  relief="flat", padx=12, pady=4, activebackground="#3a3a3a").pack(side="left", padx=4)

    foot = tk.Label(root, text="оффлайн, ничего не отправляет в сеть. секретные значения не читаются.",
                    bg=bg, fg="#666")
    foot.pack(pady=2)

    root.mainloop()


# ══════════════════════════ MAIN ══════════════════════════

def main():
    ap = argparse.ArgumentParser(description="WhatItSteals - что стиллер мог украсть")
    ap.add_argument("--cli", action="store_true", help="текстовый режим без GUI")
    ap.add_argument("--html", type=str, help="сохранить HTML-отчёт в файл")
    ap.add_argument("-o", "--out", type=str, help="сохранить текстовый отчёт в файл")
    args = ap.parse_args()

    use_gui = not (args.cli or args.out or args.html)
    if use_gui:
        # проверяем tkinter ДО скана, чтобы не молчать в консоли зря
        try:
            import tkinter  # noqa
        except ImportError:
            use_gui = False
            print("[!] tkinter не установлен - GUI недоступен, текстовый режим.")
            if platform.system() == "Linux":
                dist = ""
                try:
                    with open("/etc/os-release") as fh:
                        dist = fh.read()
                except Exception:
                    pass
                if "arch" in dist.lower():
                    print("    установить: sudo pacman -S tk")
                elif "debian" in dist.lower() or "ubuntu" in dist.lower():
                    print("    установить: sudo apt install python3-tk")
                print()

    if use_gui:
        print(f"{APP_NAME} v{APP_VERSION}: сканирую систему... (займёт до минуты)")
    findings = run_scan(verbose=True)
    recs = recommendations(findings)
    if args.out:
        open(args.out, "w", encoding="utf-8").write(build_text_report(findings, recs))
        print(f"текстовый отчёт: {args.out}")
    if args.html:
        open(args.html, "w", encoding="utf-8").write(build_html_report(findings, recs))
        print(f"HTML отчёт: {args.html}")
    if args.cli or args.out or args.html:
        print(build_text_report(findings, recs))
    else:
        try:
            import tkinter  # noqa
            run_gui()
        except Exception as e:
            print(f"[!] GUI упал: {e}")
            print(build_text_report(findings, recs))


if __name__ == "__main__":
    main()