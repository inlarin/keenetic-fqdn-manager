# Keenetic FQDN Manager

GUI для управления FQDN-маршрутами и IP-маршрутами на роутерах Keenetic (и OEM-форках типа Netcraze). Один `.exe`, без зависимостей.

## Файлы

- `dist/KeeneticFqdnManager.exe` — готовое приложение (~12 МБ), самодостаточное
- `kn_gui/` — пакет-исходник. Точка входа — `main.py`, UI собирается в `kn_gui/app.py` (App + вкладки). Логика бэкграунд-потока вынесена в `kn_gui/worker.py`; RCI HTTP-транспорт — в `kn_gui/rci_client.py`
- `data/services.json` — встроенный каталог сервисов
- `build.bat` — скрипт пересборки через PyInstaller (см. `KeeneticFqdnManager.spec`)
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
python -m pip install -r requirements-dev.txt
build.bat
```

## Тесты

Non-UI слои покрыты pytest (тесты в `tests/`, запуск без Tkinter и без живого роутера):

```bash
python -m pytest tests/
```

CI-workflow `.github/workflows/test.yml` прогоняет тесты на каждом push/PR на Python 3.10–3.13.
CI-workflow `.github/workflows/release.yml` автоматически собирает `.exe` и прикладывает к GitHub Release при push тега `v*`.

Если `pip install` валится по таймауту на pypi.org — прошивайте `python_pypi` через VPN (уже в каталоге).

## Известные ограничения

- **Основной транспорт — Telnet** (порт 23). Пароль летит по LAN в открытом виде. Альтернативный RCI HTTP-клиент с challenge-response реализован в `kn_gui/rci_client.py` — он не требует plaintext пароля и не зависит от Telnet-компонента, но пока используется только для чтения снапшотов; запись (apply, create, delete) всё ещё идёт через Telnet. Если ваш роутер в недоверенной сети — выключите Telnet-компонент и ждите полной миграции.
- **FQDN-маршрутизация требует, чтобы клиенты использовали роутер как DNS.** Android Private DNS / iOS Encrypted DNS / браузерный DoH ломают механизм — роутер не видит резолв. Для форсирования — скрипт `kn_block_doh.py` в корне репозитория (блокирует популярные DoH/DoT endpoint'ы).
- **IPv4 only.** FQDN-группы и `ip route` не транслируют AAAA-записи и не маршрутизируют IPv6 через VPN. Утилита `kn_block_ipv6.py` отключает IPv6 на LAN, чтобы закрыть leak.
- **Таймаут логина — 8 секунд.** При неверном пароле падает быстро (v0.2.0+).
