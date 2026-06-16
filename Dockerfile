# Используем легкий образ Python
FROM python:3.12-slim

# Устанавливаем системные зависимости для работы с ML (если нужны)
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Устанавливаем рабочую директорию внутри контейнера
WORKDIR /app

# Копируем файл зависимостей
COPY requirements.txt .

# Устанавливаем библиотеки
RUN pip install --no-cache-dir -r requirements.txt

# Копируем весь проект в контейнер
COPY . .

# Открываем порт, на котором работает Flask (обычно 5000)
EXPOSE 5000

# Команда для запуска приложения
CMD ["python", "main.py"]