# Сборка из исходников (Windows)

Эта инструкция — для тех, кто хочет собрать NetRuleRouter самостоятельно.
Если вы просто хотите пользоваться программой — скачайте готовый архив со
страницы релизов и следуйте [быстрому старту](quickstart.md).

Эта страница — про сборку под **Windows 10/11 (64-bit)**. Инструкция для
Linux появится отдельным документом (`building-linux.md`), когда Linux-сборка
станет поддерживаемой; macOS — дальше по плану.

## Что нужно установить

| Софт | Версия | Зачем |
|------|--------|-------|
| [Git](https://git-scm.com/download/win) | любая свежая | клонировать репозиторий |
| [Rust (rustup)](https://rustup.rs/) | ставит rustup | вся основная кодовая база |
| [Visual Studio 2022 Build Tools](https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022) | 17.x | компилятор MSVC и Windows SDK |
| [Qt 6](https://www.qt.io/download-open-source) | 6.11.x (msvc2022_64) | графический интерфейс |
| [CMake](https://cmake.org/download/) | 3.26+ | сборка нативной Qt-части |

Подробности по каждому пункту:

### Rust

Установите [rustup](https://rustup.rs/) — при первом запуске сборки он сам
скачает нужную версию тулчейна: она зафиксирована в `rust-toolchain.toml`
(сейчас `1.94.1`), вручную выбирать ничего не нужно. Целевая платформа —
`x86_64-pc-windows-msvc` (ставится по умолчанию на Windows).

### Visual Studio 2022 Build Tools

Полная Visual Studio не обязательна — достаточно Build Tools. При установке
отметьте рабочую нагрузку **«Разработка классических приложений на C++»**
(Desktop development with C++): она включает компилятор MSVC v143 и
Windows SDK. Без MSVC не соберётся ни Rust-часть (msvc-target), ни Qt-хост.

### Qt 6

Скачайте официальный [онлайн-инсталлятор Qt](https://www.qt.io/download-open-source)
(open-source, LGPLv3). В инсталляторе выберите:

- **Qt 6.11.x → MSVC 2022 64-bit** — базовый комплект уже содержит все нужные
  модули (Core, Gui, Qml, Quick, QuickControls2, Widgets); дополнительные
  библиотеки (Charts, Data Visualization и т.п.) не требуются.

Путь по умолчанию сборка находит сама: берётся самая свежая версия из
`C:\Qt\<версия>\msvc2022_64` (например `C:\Qt\6.11.1\msvc2022_64`).
Если Qt установлен в другое место — см. раздел «Переменные окружения» ниже.

> Комплект должен быть именно **MSVC**, не MinGW — иначе линковка упадёт.

### CMake

CMake 3.26+ должен быть доступен в `PATH` (проверка: `cmake --version`).
Можно поставить отдельным инсталлятором (галочка «Add CMake to PATH») или
как компонент Visual Studio Build Tools.

## Сборка

```powershell
# 1. Клонировать репозиторий
git clone https://github.com/kroxiksut/net-rule-router.git
cd net-rule-router

# 2. Проверить окружение и создать .env
powershell -ExecutionPolicy Bypass -File .\scripts\bootstrap.ps1

# 3. Собрать релизные бинарники: GUI-лаунчер, нативный Qt-хост, службу
cargo build --release -p nrr-launcher -p nrr-qt-host -p nrr-windows-service

# 4. Запустить
.\target\release\NetRuleRouter.exe          # основное окно
.\target\release\NetRuleRouterTray.exe      # трей
```

Первая сборка занимает заметное время: cargo собирает значительную часть
workspace, а CMake внутри `nrr-qt-host` собирает C++-хост.

### Фоновая служба

Служба применяет и поддерживает политику маршрутизации. Установка требует
прав администратора (UAC-запрос поднимается автоматически).

Самый простой способ — из самого приложения: **Настройки → «Управление
службой» → «Установить службу»**. Там же — запуск, остановка, перезапуск,
удаление и статус.

Из консоли — те же операции скриптами:

```powershell
.\scripts\install-service.ps1 -Profile release   # установить и запустить
.\scripts\service-status.ps1                     # проверить состояние
.\scripts\uninstall-service.ps1                  # удалить
```

### Dev-сборка (для тех, кто меняет код)

Всё то же самое без `--release` — быстрее компилируется, с отладочной
информацией, бинарники в `target\debug\`:

```powershell
cargo build -p nrr-launcher -p nrr-qt-host -p nrr-windows-service
.\target\debug\NetRuleRouter.exe
.\scripts\install-service.ps1      # без -Profile возьмёт самый свежий бинарник (dev или release)
```

### Проверка качества (для контрибьюторов)

```powershell
# fmt + clippy + тесты + аудит лицензий/зависимостей
powershell -ExecutionPolicy Bypass -File .\scripts\check.ps1 -RequireCargoDeny
```

Для флага `-RequireCargoDeny` нужен [cargo-deny](https://github.com/EmbarkStudios/cargo-deny):
`cargo install cargo-deny`. Без него — тот же скрипт без флага.

## Переменные окружения

| Переменная | Когда нужна | Пример |
|------------|-------------|--------|
| `CMAKE_PREFIX_PATH` | Qt установлен не под `C:\Qt` или нужна конкретная версия | `D:\Qt\6.11.1\msvc2022_64\lib\cmake` |
| `NRR_QT_HOST_GENERATOR` | нестандартный генератор CMake (по умолчанию `Visual Studio 17 2022`) | `Ninja` |
| `NRR_RUST_TARGET` | нестандартный rust-target (по умолчанию `x86_64-pc-windows-msvc`) | — |

Задать на время сессии PowerShell:

```powershell
$env:CMAKE_PREFIX_PATH = "D:\Qt\6.11.1\msvc2022_64\lib\cmake"
cargo build --release -p nrr-launcher -p nrr-qt-host -p nrr-windows-service
```

## Частые проблемы

**`CMAKE_PREFIX_PATH is not set and default Qt CMake path ... was not found`**
— сборка не нашла Qt. Установите Qt 6.11 (msvc2022_64) или укажите путь через
`CMAKE_PREFIX_PATH` (см. выше).

**`cmake: command not found` / `'cmake' is not recognized`**
— CMake нет в `PATH`. Переустановите с галочкой «Add CMake to PATH» или
добавьте путь вручную, затем перезапустите терминал.

**Ошибки линковки с упоминанием Qt-библиотек**
— почти всегда выбран не тот комплект Qt (MinGW вместо MSVC) или разрядность
не x64. Нужен именно **MSVC 2022 64-bit**.

**Собранный `NetRuleRouter.exe` не запускается на другой машине**
— локальная сборка (и dev, и release) не переносима: пути к QML-файлам и
локалям привязаны к дереву исходников на машине сборки. Для запуска «где
угодно» используйте готовый релизный архив со страницы релизов.

---

Английская версия: [docs/en/building-windows.md](../en/building-windows.md).
