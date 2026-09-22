# WhatItSteals

Оффлайн-утилита для жертв стиллеров: показывает, **какие данные malware мог выкачать** с этого ПК, и что делать в первую очередь.

## Почему

После взлома жертва обычно не знает, что именно утекло: пароли? кошельки? Telegram? WhatItSteals сканирует те же таргеты, что собирают реальные стиллеры (RedLine, Lumma, Vidar, StealC), и показывает, что было доступно вору.

## Принципы

- **Оффлайн.** Ноль сетевых запросов, ноль зависимостей (чистый Python 3 stdlib).
- **Секреты не извлекаются.** Приложение читает только метаданные: домены, счётчики, имена файлов. Пароли -> `gmail.com: 3 записи`, токены -> `сессия Discord найдена`. Отчёт бесполезен для мошенника и его можно публиковать.
- **Кроссплатформенность.** Windows / macOS / Linux, GUI (tkinter) с фолбэком в CLI.

## Что сканирует

| Категория | Таргеты |
|---|---|
| Браузеры | Chromium (Chrome, Edge, Brave, Opera, Yandex, Vivaldi...), Firefox-семейство: пароли, cookies, автозаполнение, карты |
| Крипта | Десктоп-кошельки (Exodus, Electrum, Atomic, Bitcoin Core...), расширения (MetaMask, Phantom, TronLink, OKX, Rabby...) |
| Мессенджеры | Discord (токен из leveldb), Telegram (tdata) |
| Игры | Steam (ssfn, loginusers) |
| Ключи | SSH, GPG, RDP, KeePass (*.kdbx), FileZilla, OpenVPN |
| Файлы | Документы/рабочий стол/загрузки по маскам *password*, *seed*, *wallet*, *2fa*... |

## Использование

```bash
# GUI
python3 whatitsteals.py

# CLI + экспорт
python3 whatitsteals.py --cli -o report.txt --html report.html
```

Готовые бинарники: раздел Releases (собираются GitHub Actions для Win/macOS/Linux при теге `v*`).

## Сборка из исходников

```bash
pip install pyinstaller
pyinstaller --onefile --noconsole whatitsteals.py
```

## Сборка через GitHub Actions

`.github/workflows/build.yml`:
- матричный билд **windows / ubuntu / macos** через PyInstaller
- артефакты при каждом запуске, **релиз с бинарниками** при пуше тега `v*`

```bash
git tag v1.0.0 && git push origin v1.0.0   # соберёт и выложит релиз
```

## Дисклеймер

Инструмент для пост-инцидентной диагностики на **своём** ПК. Он не декодирует и не показывает чужие/свои секреты - по design.

## Лицензия

MIT
