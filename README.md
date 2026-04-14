# Keenetic FQDN Manager

GUI для управления FQDN-маршрутами и IP-маршрутами на роутерах Keenetic (и OEM-форках типа Netcraze). Один `.exe`, без зависимостей.

## Файлы

- `dist/KeeneticFqdnManager.exe` — готовое приложение (~12 МБ), самодостаточное
- `kn_router_gui.py` — исходник (~1240 строк)
- `services.json` — встроенный каталог сервисов (22 сервиса)
- `build.bat` — скрипт пересборки
- Настройки UI (геометрия окна, последний host/user/interface) сохраняются в `%APPDATA%\KeeneticFqdnManager\ui.json`. Пароль **никогда** не сохраняется.

## Использование

1. Запустить `KeeneticFqdnManager.exe`.
2. Ввести host / user / пароль → `Connect` (или Enter в поле пароля). Статус-точка слева обновится: жёлтая → зелёная.
3. В dropdown `Interface` выбрать VPN-туннель (приложение предложит подключённый SSTP/Wireguard/OpenVPN автоматически).
4. Вкладка **Services** — чекбоксы слева, детали выбранного сервиса справа. Применённые уже на роутере помечены `● iface (kill)`. Apply создаёт/обновляет.
5. Вкладка **Current state** — видно все FQDN-группы (📁) и IP-маршруты (🌐) с пометкой `exclusive (kill switch)` или `unprotected`.
6. Вкладка **Catalog** — статистика текущего каталога + импорт с URL/файла.

## Горячие клавиши

| Клавиша | Действие |
|---|---|
| `Enter` в поле пароля | Connect |
| `Ctrl+Enter` | Apply selected |
| `F5` | Refresh state |
| `Esc` | Disconnect |

## Что делает kill switch

Чекбокс «Exclusive / Kill switch» добавляет `reject` к командам `ip route` и `dns-proxy route`. Семантика: пока VPN up — трафик идёт через туннель; если VPN упал — пакеты **дропаются**, а не утекают через ISP.

## Формат каталога (services.json)

```json
{
  "schema_version": 1,
  "catalog_version": "1.0.0",
  "catalog_name": "My catalog",
  "services": [
    {
      "id": "service_id",
      "name": "Human Name",
      "category": "AI | Video | Messaging | Social | Music | Dev | Productivity | Content",
      "description": "Short description",
      "fqdn": ["example.com", "api.example.com"],
      "ipv4_cidr": ["1.2.3.0/24"]
    }
  ]
}
```

- `id` → имя `object-group fqdn` на роутере (`[A-Za-z][A-Za-z0-9_]{0,31}`).
- `fqdn` — один домен на строку, поддомены подхватываются автоматически роутером.
- `ipv4_cidr` — CIDR формат, приложение конвертирует в `network mask`.

## Сборка из исходников

Требуется Python 3.10+ на Windows. Tkinter встроен.

```batch
python -m pip install pyinstaller
build.bat
```

Если `pip install` валится по таймауту на pypi.org — прошивайте `python_pypi` через VPN (уже в каталоге).

## Известные ограничения

- **Только telnet** (порт 23). Web-API 5.x использует `x-ndw2-interactive` с непубличным алгоритмом.
- **FQDN-маршрутизация требует, чтобы клиенты использовали роутер как DNS.** Android Private DNS / iOS Encrypted DNS ломают механизм — роутер не видит резолв.
- **Таймаут логина — 8 секунд.** При неверном пароле падает быстро (v0.2.0+).
