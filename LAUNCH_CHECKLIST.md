# GrowthLock — чеклист запуска

## 1. Что не загружать в GitHub

Не загружать:

```text
.env
.data/
node_modules/
```

В GitHub должны быть только код и шаблоны настроек.

## 2. Переменные окружения на хостинге

Минимум для Render/Railway/VPS:

```env
NODE_ENV=production
PORT=3000
AI_PROVIDER=openrouter
OPENROUTER_API_KEY=your_openrouter_api_key_here
OPENROUTER_MODEL=openai/gpt-oss-20b:free
AUTH_SECRET=длинная_случайная_строка
DB_FILE=/var/data/growthlock-db.json
ALLOWED_ORIGINS=https://your-site.onrender.com
```

## 3. База пользователей

Сейчас серверная база — JSON-файл:

```text
.data/growthlock-db.json
```

Для Render нужен Persistent Disk и:

```env
DB_FILE=/var/data/growthlock-db.json
```

Если нет persistent disk, данные могут стереться при redeploy.

## 4. Проверка перед запуском

```bash
npm install
npm run check
npm start
```

Открыть:

```text
http://localhost:3000/health
http://localhost:3000/ready
```

## 5. После запуска проверить

- регистрация;
- вход;
- оценка цели AI;
- сохранение цели;
- добавление дневной задачи;
- генерация AI-теста;
- проверка теста;
- начисление навыков;
- выход/повторный вход;
- сохранение прогресса после перезапуска сервера.

## 6. Что улучшить следующим крупным шагом

Для большого публичного проекта лучше перейти с JSON-файла на PostgreSQL/Supabase. JSON-база подходит для MVP и малого теста, но не для высокой нагрузки.
