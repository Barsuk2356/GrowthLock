import express from 'express';
import 'dotenv/config';
import path from 'path';
import fs from 'fs/promises';
import crypto from 'crypto';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// AI provider:
// - deepseek: uses DEEPSEEK_API_KEY and DEEPSEEK_MODEL
// - openrouter: uses OPENROUTER_API_KEY and OPENROUTER_MODEL
const AI_PROVIDER = (process.env.AI_PROVIDER || (process.env.DEEPSEEK_API_KEY ? 'deepseek' : 'openrouter')).toLowerCase();
const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY;
const OPENROUTER_MODEL = process.env.OPENROUTER_MODEL || 'openai/gpt-oss-20b:free';
const OPENROUTER_FALLBACK_MODELS = (process.env.OPENROUTER_FALLBACK_MODELS || 'meta-llama/llama-3.2-3b-instruct:free,qwen/qwen3-next-80b-a3b-instruct:free,google/gemma-4-26b-a4b-it:free,openai/gpt-oss-120b:free')
  .split(',')
  .map((model) => model.trim())
  .filter(Boolean);
const DEEPSEEK_API_KEY = process.env.DEEPSEEK_API_KEY;
const DEEPSEEK_MODEL = process.env.DEEPSEEK_MODEL || 'deepseek-chat';
const OLLAMA_BASE_URL = (process.env.OLLAMA_BASE_URL || 'http://127.0.0.1:11434').replace(/\/$/, '');
const OLLAMA_MODEL = process.env.OLLAMA_MODEL || 'qwen2.5:1.5b';
const quizzes = new Map();
const DB_FILE = process.env.DB_FILE || path.join(__dirname, '.data', 'growthlock-db.json');
const NODE_ENV = process.env.NODE_ENV || 'development';
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map((origin) => origin.trim())
  .filter(Boolean);
const RATE_LIMIT_WINDOW_MS = Number(process.env.RATE_LIMIT_WINDOW_MS || 60_000);
const RATE_LIMIT_MAX = Number(process.env.RATE_LIMIT_MAX || 90);

app.set('trust proxy', 1);

app.use((req, res, next) => {
  const origin = req.headers.origin;
  const requestHost = req.headers.host;
  let originHost = '';

  try {
    originHost = origin ? new URL(origin).host : '';
  } catch (_) {
    originHost = '';
  }

  // Разрешаем:
  // 1) запросы без Origin;
  // 2) тот же самый адрес, с которого открыт сайт;
  // 3) localhost;
  // 4) локальную Wi-Fi сеть: 192.168.x.x / 10.x.x.x / 172.16-31.x.x;
  // 5) домены из ALLOWED_ORIGINS.
  const isSameOrigin = origin && requestHost && originHost === requestHost;
  const isLocalOrigin = origin && /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin);
  const isLanOrigin = origin && /^https?:\/\/((192\.168\.\d{1,3}\.\d{1,3})|(10\.\d{1,3}\.\d{1,3}\.\d{1,3})|(172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}))(\:\d+)?$/.test(origin);
  const isAllowedOrigin = !origin || isSameOrigin || isLocalOrigin || isLanOrigin || ALLOWED_ORIGINS.includes(origin);

  if (isAllowedOrigin) {
    res.setHeader('Access-Control-Allow-Origin', origin || '*');
    res.setHeader('Vary', 'Origin');
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer-when-downgrade');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  if (req.method === 'OPTIONS') return res.sendStatus(isAllowedOrigin ? 204 : 403);
  if (!isAllowedOrigin) return res.status(403).json({ error: 'Origin is not allowed' });
  next();
});

const rateBuckets = new Map();
app.use((req, res, next) => {
  if (req.method === 'GET' && !req.path.startsWith('/api/')) return next();
  const key = `${req.ip}:${req.path}`;
  const now = Date.now();
  const bucket = rateBuckets.get(key) || { count: 0, resetAt: now + RATE_LIMIT_WINDOW_MS };
  if (now > bucket.resetAt) {
    bucket.count = 0;
    bucket.resetAt = now + RATE_LIMIT_WINDOW_MS;
  }
  bucket.count += 1;
  rateBuckets.set(key, bucket);
  res.setHeader('X-RateLimit-Limit', String(RATE_LIMIT_MAX));
  res.setHeader('X-RateLimit-Remaining', String(Math.max(0, RATE_LIMIT_MAX - bucket.count)));
  if (bucket.count > RATE_LIMIT_MAX) return res.status(429).json({ error: 'Too many requests. Попробуй чуть позже.' });
  next();
});

app.use(express.json({ limit: '1mb' }));
app.use(express.static(__dirname, {
  etag: true,
  maxAge: NODE_ENV === 'production' ? '1h' : 0
}));

function cleanupQuizzes() {
  const now = Date.now();
  for (const [id, quiz] of quizzes.entries()) {
    if (now - quiz.createdAt > 60 * 60 * 1000) quizzes.delete(id);
  }
}

async function readDb() {
  try {
    const raw = await fs.readFile(DB_FILE, 'utf8');
    const parsed = JSON.parse(raw);
    return {
      users: parsed.users && typeof parsed.users === 'object' ? parsed.users : {}
    };
  } catch (error) {
    if (error.code !== 'ENOENT') console.warn('DB read error:', error.message);
    return { users: {} };
  }
}

async function writeDb(db) {
  await fs.mkdir(path.dirname(DB_FILE), { recursive: true });
  const tempFile = `${DB_FILE}.tmp`;
  try {
    await fs.copyFile(DB_FILE, `${DB_FILE}.bak`);
  } catch (_) {
    // First write: no backup yet.
  }
  await fs.writeFile(tempFile, JSON.stringify(db, null, 2), 'utf8');
  await fs.rename(tempFile, DB_FILE);
}

function hashPassword(login, password, salt = '') {
  // PBKDF2 is built into Node.js and is much safer than a plain hash for stored passwords.
  return crypto.pbkdf2Sync(
    String(password),
    `${login}:${salt}:${process.env.AUTH_SECRET || 'growthlock-local-secret'}`,
    120_000,
    64,
    'sha512'
  ).toString('hex');
}

function legacyPasswordHash(login, password) {
  return crypto.createHash('sha256').update(`${login}:${password}:${process.env.AUTH_SECRET || 'growthlock-local-secret'}`).digest('hex');
}

function publicUser(user) {
  return {
    login: user.login,
    displayName: user.displayName,
    createdAt: user.createdAt
  };
}

function createToken() {
  return crypto.randomBytes(32).toString('hex');
}

function normalizeLogin(value) {
  return String(value || '').trim().toLowerCase();
}

async function requireUser(req, res) {
  const login = normalizeLogin(req.body.login || req.query.login);
  const token = String(req.body.token || req.query.token || '');
  const db = await readDb();
  const user = db.users[login];
  if (!user || !token || user.sessionToken !== token) {
    res.status(401).json({ error: 'Unauthorized' });
    return null;
  }
  return { db, user, login };
}

function getProviderConfig() {
  if (AI_PROVIDER === 'ollama') {
    return {
      provider: 'Ollama',
      apiKey: '',
      requiresApiKey: false,
      model: OLLAMA_MODEL,
      url: `${OLLAMA_BASE_URL}/v1/chat/completions`,
      headers: {}
    };
  }

  if (AI_PROVIDER === 'deepseek') {
    return {
      provider: 'DeepSeek',
      apiKey: DEEPSEEK_API_KEY,
      requiresApiKey: true,
      model: DEEPSEEK_MODEL,
      url: process.env.DEEPSEEK_BASE_URL || 'https://api.deepseek.com/chat/completions',
      headers: {}
    };
  }

  return {
    provider: 'OpenRouter',
    apiKey: OPENROUTER_API_KEY,
    requiresApiKey: true,
    model: OPENROUTER_MODEL,
    url: 'https://openrouter.ai/api/v1/chat/completions',
    headers: {
      'HTTP-Referer': 'http://localhost:3000',
      'X-Title': 'GrowthLock Prototype'
    }
  };
}

function normalizeDifficulty(value) {
  return ['easy', 'medium', 'hard'].includes(value) ? value : 'medium';
}

function getDifficultyProfile(value) {
  const difficulty = normalizeDifficulty(value);
  const profiles = {
    easy: {
      label: 'лёгкий',
      threshold: 40,
      minQuestionScore: 10,
      questionStyle: 'Задай очень простые вопросы на базовое понимание: что это значит, зачем это нужно, как применить в одном примере. Не используй сложные термины, редкие детали и академические формулировки.',
      checkStyle: 'Проверяй мягко. Засчитывай ответы, если пользователь своими словами понял общий смысл. Не требуй точных терминов, полного списка этапов и идеальной структуры.'
    },
    medium: {
      label: 'средний',
      threshold: 50,
      minQuestionScore: 20,
      questionStyle: 'Задай понятные вопросы средней сложности простыми словами: главная мысль, почему это важно, как применить на практике. Если нужен термин, сразу объясни его простыми словами в вопросе. Не задавай вопросы в стиле экзамена по учебнику.',
      checkStyle: 'Проверяй по смыслу и достаточно лояльно. Если ответ написан своими словами, по теме и показывает понимание основной идеи, ставь хороший балл. Не снижай сильно за неполный список шагов, если смысл понятен.'
    },
    hard: {
      label: 'сложный',
      threshold: 70,
      minQuestionScore: 40,
      questionStyle: 'Задай более глубокие вопросы, но всё равно простыми словами: сравнить идеи, объяснить причину, применить к реальной ситуации. Этот режим требовательнее и лучше помогает усвоить материал, но вопросы не должны быть запутанными.',
      checkStyle: 'Проверяй строже, но справедливо. Ответ должен показывать глубокое понимание и применение идеи. Не требуй дословности, но не засчитывай общую воду.'
    }
  };
  return { difficulty, ...profiles[difficulty] };
}

function extractJson(text) {
  const cleaned = String(text || '')
    .replace(/^```json\s*/i, '')
    .replace(/^```\s*/i, '')
    .replace(/```$/i, '')
    .trim();

  try {
    return JSON.parse(cleaned);
  } catch (_) {
    const match = cleaned.match(/\{[\s\S]*\}/);
    if (!match) throw new Error('AI did not return JSON');
    return JSON.parse(match[0]);
  }
}

async function callAIJson(messages, temperature = 0.25, schemaHint = '') {
  const content = await callAI(messages, temperature);
  try {
    return extractJson(content);
  } catch (firstError) {
    // Some models occasionally return almost-valid JSON: unescaped quotes, trailing text,
    // a missed comma, etc. Ask the model once to repair it instead of failing the user.
    const repaired = await callAI([
      {
        role: 'system',
        content:
          'Ты JSON-repair модуль. Твоя задача — получить текст с почти валидным JSON и вернуть ТОЛЬКО исправленный валидный JSON. Никакого markdown, никаких пояснений, только JSON. Сохрани смысл и структуру. Если массив или поле оборвались, аккуратно заверши JSON.'
      },
      {
        role: 'user',
        content: `Ошибка парсинга: ${firstError.message}

Ожидаемая схема:
${schemaHint}

Текст для исправления:
${content}`
      }
    ], 0);
    return extractJson(repaired);
  }
}

function parseProviderError(raw, fallback = 'AI request failed') {
  let message = raw || fallback;
  try {
    const parsed = JSON.parse(raw);
    message = parsed.error?.message || parsed.error || parsed.message || message;
    if (typeof message !== 'string') message = JSON.stringify(message);
  } catch (_) {
    // Keep raw text.
  }
  return message;
}

function shouldTryFallback(message, status) {
  const text = String(message || '').toLowerCase();
  return status === 429
    || status === 402
    || text.includes('access denied')
    || text.includes('security policy')
    || text.includes('rate-limited')
    || text.includes('insufficient credits')
    || text.includes('provider returned error');
}

function getModelsToTry(config) {
  if (config.provider !== 'OpenRouter') return [config.model];
  return [...new Set([config.model, ...OPENROUTER_FALLBACK_MODELS])];
}

async function callProvider(config, model, messages, temperature) {
  const headers = {
    'Content-Type': 'application/json',
    ...config.headers
  };
  if (config.apiKey) headers.Authorization = `Bearer ${config.apiKey}`;

  const response = await fetch(config.url, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      model,
      temperature,
      messages,
      stream: false
    })
  });

  const raw = await response.text();
  if (!response.ok) {
    const message = parseProviderError(raw, `${config.provider} request failed`);
    const error = new Error(`${config.provider}: ${message}`);
    error.status = response.status;
    error.providerMessage = message;
    error.model = model;
    throw error;
  }

  const data = JSON.parse(raw);
  return {
    content: data.choices?.[0]?.message?.content || '',
    model
  };
}

async function callAI(messages, temperature = 0.25) {
  const config = getProviderConfig();

  if (config.requiresApiKey !== false && !config.apiKey) {
    const error = new Error(`${config.provider} API key is not set`);
    error.status = 500;
    throw error;
  }

  const models = getModelsToTry(config);
  const errors = [];

  for (const model of models) {
    try {
      const result = await callProvider(config, model, messages, temperature);
      return result.content;
    } catch (error) {
      errors.push(`${model}: ${error.providerMessage || error.message}`);
      if (!shouldTryFallback(error.providerMessage || error.message, error.status)) {
        throw error;
      }
    }
  }

  const finalError = new Error(
    `${config.provider}: запрос заблокирован или недоступен для всех доступных моделей. `
    + `Попробуй VPN, другой API-ключ, другую модель или другого провайдера. Детали: ${errors.join(' | ')}`
  );
  finalError.status = 502;
  throw finalError;
}

app.get('/health', async (_, res) => {
  let dbOk = true;
  try {
    const db = await readDb();
    dbOk = Boolean(db && db.users);
  } catch (_) {
    dbOk = false;
  }
  const config = getProviderConfig();
  res.json({
    ok: dbOk,
    service: 'GrowthLock',
    version: process.env.npm_package_version || '1.0.0',
    uptime: Math.round(process.uptime()),
    env: NODE_ENV,
    db: dbOk ? 'ok' : 'error',
    aiProvider: config.provider,
    aiConfigured: config.requiresApiKey === false ? true : Boolean(config.apiKey)
  });
});

app.get('/ready', async (_, res) => {
  const config = getProviderConfig();
  if (config.requiresApiKey !== false && !config.apiKey) return res.status(503).json({ ok: false, error: `${config.provider} API key is not set` });
  try {
    await readDb();
    res.json({ ok: true });
  } catch (error) {
    res.status(503).json({ ok: false, error: error.message });
  }
});

app.get('/api/ai/status', (_, res) => {
  const config = getProviderConfig();
  res.json({
    connected: config.requiresApiKey === false ? true : Boolean(config.apiKey),
    provider: config.provider,
    model: config.model
  });
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const login = normalizeLogin(req.body.login);
    const displayName = String(req.body.displayName || login).trim();
    const password = String(req.body.password || '');
    if (login.length < 3) return res.status(400).json({ error: 'Логин должен быть минимум 3 символа' });
    if (password.length < 4) return res.status(400).json({ error: 'Пароль должен быть минимум 4 символа' });

    const db = await readDb();
    if (db.users[login]) return res.status(409).json({ error: 'Такой логин уже существует' });

    const user = {
      login,
      displayName,
      passwordSalt: crypto.randomBytes(16).toString('hex'),
      passwordHash: '',
      sessionToken: createToken(),
      createdAt: Date.now(),
      updatedAt: Date.now(),
      state: null
    };
    user.passwordHash = hashPassword(login, password, user.passwordSalt);
    db.users[login] = user;
    await writeDb(db);
    res.json({ user: publicUser(user), token: user.sessionToken });
  } catch (error) {
    res.status(500).json({ error: error.message || 'Registration failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const login = normalizeLogin(req.body.login);
    const password = String(req.body.password || '');
    const db = await readDb();
    const user = db.users[login];
    if (!user) return res.status(401).json({ error: 'Неверный логин или пароль' });

    const validModernHash = user.passwordSalt && user.passwordHash === hashPassword(login, password, user.passwordSalt);
    const validLegacyHash = !user.passwordSalt && user.passwordHash === legacyPasswordHash(login, password);
    if (!validModernHash && !validLegacyHash) {
      return res.status(401).json({ error: 'Неверный логин или пароль' });
    }

    // Upgrade old local prototype accounts to salted PBKDF2 on next login.
    if (!user.passwordSalt) {
      user.passwordSalt = crypto.randomBytes(16).toString('hex');
      user.passwordHash = hashPassword(login, password, user.passwordSalt);
    }
    user.sessionToken = createToken();
    user.updatedAt = Date.now();
    await writeDb(db);
    res.json({ user: publicUser(user), token: user.sessionToken, state: user.state || null });
  } catch (error) {
    res.status(500).json({ error: error.message || 'Login failed' });
  }
});

app.post('/api/auth/session', async (req, res) => {
  const auth = await requireUser(req, res);
  if (!auth) return;
  res.json({ user: publicUser(auth.user), state: auth.user.state || null });
});

app.post('/api/state/save', async (req, res) => {
  try {
    const auth = await requireUser(req, res);
    if (!auth) return;
    auth.user.state = req.body.state || {};
    auth.user.updatedAt = Date.now();
    await writeDb(auth.db);
    res.json({ ok: true, updatedAt: auth.user.updatedAt });
  } catch (error) {
    res.status(500).json({ error: error.message || 'State save failed' });
  }
});

app.post('/api/state/load', async (req, res) => {
  const auth = await requireUser(req, res);
  if (!auth) return;
  res.json({ state: auth.user.state || null, updatedAt: auth.user.updatedAt || null });
});

function makeSearchUrl(text) {
  return `https://www.google.com/search?q=${encodeURIComponent(text)}`;
}

async function fetchJson(url) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 7000);
  try {
    const response = await fetch(url, {
      signal: controller.signal,
      headers: { 'User-Agent': 'GrowthLockPrototype/1.0' }
    });
    if (!response.ok) return null;
    return await response.json();
  } catch (_) {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

async function resolveOpenLibraryUrl(title, query) {
  const search = encodeURIComponent(title || query || '');
  if (!search) return null;
  const data = await fetchJson(`https://openlibrary.org/search.json?title=${search}&limit=1`);
  const doc = data?.docs?.[0];
  if (doc?.key) {
    return {
      url: `https://openlibrary.org${doc.key}`,
      source: 'Open Library'
    };
  }
  return null;
}

async function resolveWikipediaUrl(query, lang = 'ru') {
  const search = encodeURIComponent(query || '');
  if (!search) return null;
  const data = await fetchJson(`https://${lang}.wikipedia.org/w/api.php?action=query&list=search&srsearch=${search}&utf8=1&format=json&origin=*&srlimit=1`);
  const page = data?.query?.search?.[0];
  if (page?.pageid) {
    return {
      url: `https://${lang}.wikipedia.org/?curid=${page.pageid}`,
      source: `${lang.toUpperCase()} Wikipedia`
    };
  }
  return null;
}

async function resolveRealMaterialUrl(item) {
  const type = String(item.type || '').toLowerCase();
  const title = String(item.title || '').trim();
  const query = String(item.query || title).trim();

  if (type.includes('книг')) {
    const book = await resolveOpenLibraryUrl(title, query);
    if (book) return book;
  }

  const wikiRu = await resolveWikipediaUrl(query || title, 'ru');
  if (wikiRu) return wikiRu;

  const wikiEn = await resolveWikipediaUrl(query || title, 'en');
  if (wikiEn) return wikiEn;

  // Последний вариант — не выдаём фейковую ссылку. Фронтенд покажет, что ссылка не найдена.
  return { url: '', source: 'ссылка не найдена' };
}

async function normalizeMaterialsWithRealLinks(rawMaterials) {
  const base = Array.isArray(rawMaterials) ? rawMaterials.slice(0, 12) : [];
  return Promise.all(base.map(async (item) => {
    const title = String(item.title || 'Материал для изучения').trim();
    const query = String(item.query || title).trim();
    const resolved = await resolveRealMaterialUrl({ ...item, title, query });
    return {
      type: String(item.type || 'материал').trim(),
      title,
      why: String(item.why || 'Подходит под твою цель').trim(),
      query,
      url: resolved.url,
      source: resolved.source
    };
  }));
}

app.post('/api/ai/goal-review', async (req, res) => {
  try {
    const goal = String(req.body.goal || '').trim();
    if (!goal) return res.status(400).json({ error: 'Goal is required' });

    const parsed = await callAIJson([
      {
        role: 'system',
        content:
          'Ты AI-наставник в приложении саморазвития. Проанализируй цель пользователя простыми словами. Оцени цель по шкале 0-100: конкретность, измеримость, срок, реалистичность, понятный первый шаг. Затем подбери много материалов для изучения: 8-12 пунктов, включая книги, статьи/темы для поиска, видео/курсы и практические задания. Не придумывай ссылки. Для каждого материала дай точное название и поисковый запрос; платформа сама попробует найти реальную ссылку через открытые источники вроде Open Library и Wikipedia. Также предложи 3 стартовые задачи под эту цель. Отвечай строго JSON без markdown: {"score":0-100,"verdict":"короткий статус","feedback":"короткая понятная оценка","improvedGoal":"как переписать цель лучше","problems":["что улучшить"],"nextSteps":["первый шаг"],"materials":[{"type":"книга|статья|видео|курс|задание","title":"название","why":"зачем это изучать","query":"поисковый запрос"}],"starterTasks":["задача 1","задача 2","задача 3"]}'
      },
      {
        role: 'user',
        content: `Цель пользователя: ${goal}`
      }
    ], 0.35, 'goal-review JSON: score, verdict, feedback, improvedGoal, problems[], nextSteps[], materials[], starterTasks[]');
    const config = getProviderConfig();
    const score = Math.max(0, Math.min(100, Number(parsed.score || 0)));
    const materials = await normalizeMaterialsWithRealLinks(parsed.materials);

    res.json({
      score,
      verdict: String(parsed.verdict || 'Цель проанализирована'),
      feedback: String(parsed.feedback || ''),
      improvedGoal: String(parsed.improvedGoal || ''),
      problems: Array.isArray(parsed.problems) ? parsed.problems.slice(0, 5).map(String) : [],
      nextSteps: Array.isArray(parsed.nextSteps) ? parsed.nextSteps.slice(0, 5).map(String) : [],
      materials,
      starterTasks: Array.isArray(parsed.starterTasks) ? parsed.starterTasks.slice(0, 3).map(String) : [],
      source: config.provider.toLowerCase(),
      model: config.model
    });
  } catch (error) {
    res.status(error.status || 500).json({ error: error.message || 'Failed to review goal' });
  }
});

app.post('/api/ai/explain-mistakes', async (req, res) => {
  try {
    const task = String(req.body.task || '').trim();
    const questions = Array.isArray(req.body.questions) ? req.body.questions : [];
    const answers = Array.isArray(req.body.answers) ? req.body.answers : [];
    const result = req.body.result || {};
    if (!task || questions.length !== 3 || answers.length !== 3) {
      return res.status(400).json({ error: 'Task, 3 questions and 3 answers are required' });
    }

    const parsed = await callAIJson([
      {
        role: 'system',
        content:
          'Ты AI-наставник в приложении саморазвития. Пользователь провалил или частично провалил тест. Объясни ошибки простыми словами, без унижения и без сложных терминов. Нужно: 1) коротко сказать, что он понял, 2) что именно понял неправильно или неполно, 3) как исправить ответы, 4) дать мини-план повторения, 5) предложить 2-4 материала для повторения. Не придумывай ссылки, дай только точные названия и поисковые запросы. Отвечай строго JSON без markdown: {"summary":"общий разбор","misunderstood":["ошибка"],"fixPlan":["шаг"],"betterAnswers":[{"question":"вопрос","example":"пример более сильного ответа простыми словами"}],"recommendedMaterials":[{"type":"книга|статья|видео|курс","title":"название","why":"зачем повторить","query":"поисковый запрос"}]}'
      },
      {
        role: 'user',
        content: JSON.stringify({ task, questions, answers, result }, null, 2)
      }
    ], 0.25, 'explain-mistakes JSON: summary, misunderstood[], fixPlan[], betterAnswers[], recommendedMaterials[]');
    const materials = await normalizeMaterialsWithRealLinks(parsed.recommendedMaterials);
    res.json({
      summary: String(parsed.summary || 'AI-наставник разобрал ошибки.'),
      misunderstood: Array.isArray(parsed.misunderstood) ? parsed.misunderstood.slice(0, 6).map(String) : [],
      fixPlan: Array.isArray(parsed.fixPlan) ? parsed.fixPlan.slice(0, 6).map(String) : [],
      betterAnswers: Array.isArray(parsed.betterAnswers) ? parsed.betterAnswers.slice(0, 3).map((item) => ({
        question: String(item.question || ''),
        example: String(item.example || '')
      })) : [],
      recommendedMaterials: materials
    });
  } catch (error) {
    res.status(error.status || 500).json({ error: error.message || 'Failed to explain mistakes' });
  }
});

app.post('/api/ai/quiz', async (req, res) => {
  try {
    cleanupQuizzes();
    const task = String(req.body.task || '').trim();
    const profile = getDifficultyProfile(req.body.difficulty);
    if (!task) return res.status(400).json({ error: 'Task is required' });

    const parsed = await callAIJson([
      {
        role: 'system',
        content:
          `Ты модуль образовательного сайта саморазвития. По задаче пользователя составь мини-тест из 3 вопросов. ОБЯЗАТЕЛЬНО формулируй вопросы простыми словами, как для обычного пользователя, не как для преподавателя на экзамене. Не используй сложные канцелярские фразы вроде «в чём заключается применение методологии» — вместо этого спрашивай проще: «как это помогает в проекте?» или «что нужно сделать сначала?». Сложность теста: ${profile.label}. Правило сложности: ${profile.questionStyle} Вопросы должны проверять ПРАВИЛЬНОЕ ПОНИМАНИЕ материала, книги, лекции или темы из задачи, а не просто факт выполнения. Если задача про известную книгу — спрашивай по ключевым идеям этой книги с учётом выбранной сложности. Если задача про лекцию/курс без названия — спрашивай главную идею, практический вывод и применение. Для каждого вопроса создай скрытый критерий проверки, соответствующий сложности. Отвечай строго JSON без markdown: {"material":"что именно проверяется","questions":[{"question":"простой вопрос пользователю","rubric":"какие идеи должен содержать правильный ответ","ideal":"пример правильного ответа кратко"},{"question":"...","rubric":"...","ideal":"..."},{"question":"...","rubric":"...","ideal":"..."}]}`
      },
      {
        role: 'user',
        content: `Задача пользователя: ${task}
Сложность теста: ${profile.label}`
      }
    ], 0.35, 'quiz JSON: material, questions[{question,rubric,ideal}]');
    const rawQuestions = Array.isArray(parsed.questions) ? parsed.questions.slice(0, 3) : [];
    if (rawQuestions.length !== 3) throw new Error('AI returned invalid questions');

    const normalized = rawQuestions.map((item) => ({
      question: String(item.question || '').trim(),
      rubric: String(item.rubric || '').trim(),
      ideal: String(item.ideal || '').trim()
    }));

    if (normalized.some((item) => !item.question)) throw new Error('AI returned empty questions');

    const quizId = crypto.randomUUID();
    const config = getProviderConfig();
    quizzes.set(quizId, {
      task,
      material: String(parsed.material || task),
      difficulty: profile.difficulty,
      threshold: profile.threshold,
      minQuestionScore: profile.minQuestionScore,
      questions: normalized,
      createdAt: Date.now()
    });

    res.json({
      quizId,
      source: config.provider.toLowerCase(),
      model: config.model,
      difficulty: profile.difficulty,
      difficultyLabel: profile.label,
      threshold: profile.threshold,
      material: String(parsed.material || task),
      questions: normalized.map((item) => item.question)
    });
  } catch (error) {
    res.status(error.status || 500).json({ error: error.message || 'Failed to generate quiz' });
  }
});

app.post('/api/ai/check-quiz', async (req, res) => {
  try {
    cleanupQuizzes();
    const quizId = String(req.body.quizId || '').trim();
    const task = String(req.body.task || '').trim();
    const questions = Array.isArray(req.body.questions) ? req.body.questions : [];
    const answers = Array.isArray(req.body.answers) ? req.body.answers : [];
    const storedQuiz = quizId ? quizzes.get(quizId) : null;
    const profile = storedQuiz ? getDifficultyProfile(storedQuiz.difficulty) : getDifficultyProfile(req.body.difficulty);

    if (!task || answers.length !== 3 || (!storedQuiz && questions.length !== 3)) {
      return res.status(400).json({ error: 'Task, quizId/questions and 3 answers are required' });
    }

    const checkPayload = storedQuiz
      ? {
          task: storedQuiz.task,
          material: storedQuiz.material,
          difficulty: profile.label,
          threshold: profile.threshold,
          questions: storedQuiz.questions.map((item, index) => ({
            question: item.question,
            hiddenRubric: item.rubric,
            idealAnswer: item.ideal,
            userAnswer: answers[index]
          }))
        }
      : {
          task,
          material: task,
          difficulty: profile.label,
          threshold: profile.threshold,
          questions: questions.map((question, index) => ({
            question,
            hiddenRubric: 'Оцени по смыслу вопроса и задачи. Ответ должен быть конкретным, верным и показывать понимание.',
            idealAnswer: 'Нет заранее сохранённого эталона.',
            userAnswer: answers[index]
          }))
        };

    const parsed = await callAIJson([
      {
        role: 'system',
        content:
          `Ты проверяющий мини-теста на сайте саморазвития. Сложность проверки: ${profile.label}. Правило проверки: ${profile.checkStyle} Проверь, насколько пользователь ПРАВИЛЬНО ПОНЯЛ материал. Оценивай смысл ответа, а не академическую точность. Пользователь может писать простыми словами, с ошибками и неполными формулировками — это нормально, если видно понимание. Используй hiddenRubric и idealAnswer как ориентир, но не требуй дословности и полного списка всех пунктов, если вопрос прямо не просит перечислить всё. Для лёгкого режима достаточно базового смысла; для среднего нужны основные идеи и пример применения; для сложного нужно более глубокое объяснение. Итоговый ориентир: общий score должен быть примерно >= ${profile.threshold}, а отдельные ответы желательно не ниже ${profile.minQuestionScore}. Если пользователь понял материал, выдай очки навыков. Навыки придумывай сам по смыслу материала: психология, критическое мышление, финансовая грамотность, сила, выносливость, управление проектами, интеллект и любые другие — список не ограничен. Количество очков выбирай сам: лёгкий тест обычно 3-8, средний 6-15, сложный 10-25. Можно дать несколько разных навыков. Если тест провален, skillPoints верни пустым массивом. Комментарии пиши простыми словами и подсказывай, что именно улучшить. Отвечай строго JSON без markdown: {"passed":true,"score":0-100,"understanding":"краткий уровень понимания","feedback":"короткий общий комментарий","perQuestion":[{"correct":true,"score":0-100,"comment":"что верно/что исправить"},{"correct":true,"score":0-100,"comment":"..."},{"correct":true,"score":0-100,"comment":"..."}],"skillPoints":[{"skill":"название навыка","points":10,"reason":"почему начислено"}]}`
      },
      {
        role: 'user',
        content: JSON.stringify(checkPayload, null, 2)
      }
    ], 0.1, 'check-quiz JSON: passed, score, understanding, feedback, perQuestion[], skillPoints[]');
    const score = Math.max(0, Math.min(100, Number(parsed.score || 0)));
    const perQuestion = Array.isArray(parsed.perQuestion) ? parsed.perQuestion.slice(0, 3) : [];
    const minScore = perQuestion.length ? Math.min(...perQuestion.map((item) => Number(item.score || 0))) : score;
    const passed = score >= profile.threshold && minScore >= profile.minQuestionScore;
    const rawSkillPoints = Array.isArray(parsed.skillPoints) ? parsed.skillPoints.slice(0, 6) : [];
    const skillPoints = passed
      ? rawSkillPoints.map((item) => ({
          skill: String(item.skill || 'Опыт').trim(),
          points: Math.max(1, Math.min(100, Number(item.points || 1))),
          reason: String(item.reason || 'AI начислил за подтверждённое понимание материала').trim()
        })).filter((item) => item.skill)
      : [];
    const config = getProviderConfig();

    res.json({
      passed,
      score,
      understanding: String(parsed.understanding || ''),
      feedback: String(parsed.feedback || ''),
      difficulty: profile.difficulty,
      difficultyLabel: profile.label,
      threshold: profile.threshold,
      perQuestion,
      skillPoints,
      source: config.provider.toLowerCase(),
      model: config.model
    });
  } catch (error) {
    res.status(error.status || 500).json({ error: error.message || 'Failed to check quiz' });
  }
});

app.use((_, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
  const config = getProviderConfig();
  console.log(`GrowthLock running: http://localhost:${PORT}`);
  console.log(`AI provider: ${config.provider} · model: ${config.model}`);
});
