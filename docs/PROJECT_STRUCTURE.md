# MiniCrypto: структура проекта

Этот документ соответствует текущему дереву исходников. Параметры и свойства безопасности описаны как поведение текущего кода, не как гарантия отсутствия дефектов.

## Основные каталоги и файлы

- `core/crypto.cpp`, `crypto.h` — шифрование/расшифрование файлов secretstream, metadata и self-test.
- `core/deniable.cpp`, `deniable.h` — экспериментальный двухслотовый fixed-size контейнер.
- `core/keygen.cpp`, `keygen.h` — Argon2id, BLAKE2b и режимные контексты.
- `core/format.cpp`, `format.h` — legacy формат v2 и проверка его заголовка.
- `core/dir_ops.cpp`, `dir_ops.h` — упаковка/распаковка MCDA архивов и операции над каталогами.
- `core/secure_memory.cpp`, `secure_memory.h` — защищённые обёртки памяти; OS memory lock best-effort.
- `core/file_ops.cpp`, `file_ops.h` — AtomicFile и best-effort secure delete.
- `ui_cli/main.cpp`, `ui.cpp`, `ui.h` — команды CLI, ввод пароля и отображение прогресса.
- `tests/test_main.cpp` — unit/integration tests.
- `docs/` — архитектурный план, security facts, отчёт тестирования и план fixed-slot контейнера.
- `.github/workflows/` — CI, release build и автоматические static/dependency checks; это не независимый криптографический аудит.
- `.RELEASE_RUNBOOK.md` — операционная инструкция сопровождающего; dot-имя не делает его секретным.

## Зависимости

- C++17 toolchain и CMake.
- libsodium.
- libargon2.
- Pkg-config используется, когда доступны соответствующие `.pc` модули; CMake также пытается найти заголовки и библиотеки напрямую.

Конкретные пакеты зависят от ОС и способа установки. Успешная сборка на одной машине не доказывает сборку на всех платформах.

## Сборка и тесты

Из корня репозитория:

```sh
cmake -S . -B build -DBUILD_TESTS=ON
cmake --build build --parallel
```

Тесты запускаются через CTest в IDE или доступном CMake workflow. Успешный прогон сообщает только о тестах, реально выполненных в данной конфигурации; он не сертифицирует безопасность.

Опция `BUILD_SHARED_LIBS` по умолчанию выключена. `BUILD_STATIC_CLI` запрашивает статическую линковку на поддерживаемых toolchain, но не гарантирует, что все системные зависимости окажутся статически включены на каждой ОС.

## Примечания по безопасности

- STANDARD/SPLIT-KEY используют Argon2id; KEY-ONLY — BLAKE2b-256, а не HKDF.
- Обычный заголовок раскрывает metadata и не целиком аутентифицирован как associated data.
- `HEADERLESS` не обеспечивает стеганографию или plausible deniability.
- Fixed-slot контейнер экспериментальный и не имеет внешнего аудита; пользователь может проверять код или самостоятельно заказывать аудит.
- Блокировка памяти и secure deletion зависят от ОС/носителя и являются best-effort; см. [Security.md](Security.md).
- Программа предоставляется «как есть». Держите проверенные резервные копии и самостоятельно решайте, приемлем ли риск.
