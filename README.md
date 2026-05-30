# OAuth2 / OpenID Connect Educational Project

## О проекте
Учебная практика посвящена изучению и практической реализации
протоколов аутентификации **OAuth 2.0** и **OpenID Connect**, 
которые применяются для безопасного входа пользователей 
в веб-приложения через сторонние сервисы,
на языке **Python** и фреймворке **Flask**

## Архитектура

Проект состоит из двух независимых Flask-приложений: 
клиента (`client/`) и провайдера (`provider/`)

+ Клиент выступает в роли OAuth-клиента и предоставляет 
пользователю интерфейс для входа через одного из поддерживаемых провайдеров
+ Провайдер реализует полноценный сервер авторизации OAuth 2.0 
с расширением OpenID Connect.

## Технологии

+ Python 3.13
+ uv
+ Flask
+ PyJWT
+ cryptography
+ Requests
+ Werkzeug
+ TailwindCSS
+ SQLite

## Запуск

*Для запуска приложений требуется менеджер пакетов **uv***

### 1. Установка основных зависимостей

`uv sync`

### 2. Генерация RSA-ключа для провайдера

`openssl genrsa -out provider/private_key.pem 2048`

### 3. Настройка .env

Необходимо создать `.env` файлы в директориях `provider/` и `client/` 
и настроить переменные окружения по образцу из `.env.example`

### 4. Запуск провайдерa (на порту 5001)

`uv run python provider/src/app.py`

### 5. Запуск клиентa (на порту 5000)

`uv run python client/src/app.py`

## Качество кода

### Установка дополнительных зависимостей

`uv sync --all-extras`

### Тесты

`PYTHONPATH=provider/src uv run pytest provider/tests/ -v`

`PYTHONPATH=client/src uv run pytest client/tests/ -v`

### Линтинг

`uv run ruff check .`

`uv run ruff format --check .`

### Проверка типов

`uv run mypy provider/src/ client/src/ --explicit-package-bases`
