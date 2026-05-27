require('dotenv').config();
const express  = require('express');
const cors     = require('cors');
const helmet   = require('helmet');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();
app.set('trust proxy', 1);
app.use(helmet());
app.use(cors({ origin: process.env.ALLOWED_ORIGIN || '*' }));
app.use(express.json());

// ── Database (lazy connect — won't crash server if DB is slow) ──
let pool;
function getPool() {
  if (!pool) {
    pool = new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: { rejectUnauthorized: false },
      connectionTimeoutMillis: 5000,
      max: 10
    });
    pool.on('error', err => console.error('DB error:', err.message));
  }
  return pool;
}

// ── Auth middleware ─────────────────────────────────────────
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET || 'dev_secret');
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// ── Health check ────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date() });
});

app.get('/', (req, res) => {
  res.json({ message: 'CricPulse API is live 🏏' });
});

// ── Auth ────────────────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  const { username, email, password, display_name } = req.body;
  if (!username || !email || !password)
    return res.status(400).json({ error: 'username, email and password required' });
  try {
    const hash = await bcrypt.hash(password, 12);
    const { rows } = await getPool().query(
      `INSERT INTO users (username,email,password_hash,display_name)
       VALUES ($1,$2,$3,$4) RETURNING id,username,email,role`,
      [username, email, hash, display_name || username]
    );
    const token = jwt.sign({ id: rows[0].id, role: rows[0].role },
      process.env.JWT_SECRET || 'dev_secret', { expiresIn: '7d' });
    res.status(201).json({ user: rows[0], token });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'Username or email already taken' });
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const { rows } = await getPool().query('SELECT * FROM users WHERE email=$1', [email]);
    if (!rows.length) return res.status(401).json({ error: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, rows[0].password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: rows[0].id, role: rows[0].role },
      process.env.JWT_SECRET || 'dev_secret', { expiresIn: '7d' });
    const { password_hash, ...user } = rows[0];
    res.json({ user, token });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/auth/me', auth, async (req, res) => {
  const { rows } = await getPool().query(
    'SELECT id,username,email,display_name,avatar_url,role,is_premium,streak_days,quiz_points,predict_points FROM users WHERE id=$1',
    [req.user.id]
  );
  res.json(rows[0]);
});

// ── Matches ─────────────────────────────────────────────────
app.get('/api/matches/live', async (req, res) => {
  try {
    const { rows } = await getPool().query(`
      SELECT m.*,
        ta.name AS team_a_name, ta.short_name AS team_a_short, ta.flag_emoji AS team_a_flag,
        tb.name AS team_b_name, tb.short_name AS team_b_short, tb.flag_emoji AS team_b_flag,
        v.name AS venue_name, v.city AS venue_city
      FROM matches m
      JOIN teams ta ON ta.id=m.team_a_id
      JOIN teams tb ON tb.id=m.team_b_id
      LEFT JOIN venues v ON v.id=m.venue_id
      WHERE m.status='live' ORDER BY m.match_date DESC`);
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/matches/upcoming', async (req, res) => {
  try {
    const { rows } = await getPool().query(`
      SELECT m.*,
        ta.name AS team_a_name, ta.short_name AS team_a_short, ta.flag_emoji AS team_a_flag,
        tb.name AS team_b_name, tb.short_name AS team_b_short, tb.flag_emoji AS team_b_flag,
        v.name AS venue_name, v.city AS venue_city
      FROM matches m
      JOIN teams ta ON ta.id=m.team_a_id
      JOIN teams tb ON tb.id=m.team_b_id
      LEFT JOIN venues v ON v.id=m.venue_id
      WHERE m.status='upcoming' AND m.match_date>=CURRENT_DATE
      ORDER BY m.match_date ASC LIMIT 20`);
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/matches/:id', async (req, res) => {
  try {
    const { rows } = await getPool().query(`
      SELECT m.*,
        ta.name AS team_a_name, ta.flag_emoji AS team_a_flag,
        tb.name AS team_b_name, tb.flag_emoji AS team_b_flag,
        v.name AS venue_name, v.city AS venue_city
      FROM matches m
      JOIN teams ta ON ta.id=m.team_a_id
      JOIN teams tb ON tb.id=m.team_b_id
      LEFT JOIN venues v ON v.id=m.venue_id
      WHERE m.id=$1`, [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    const { rows: scorecards } = await getPool().query(
      'SELECT * FROM scorecards WHERE match_id=$1 ORDER BY innings_number', [req.params.id]);
    res.json({ match: rows[0], scorecards });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Players ─────────────────────────────────────────────────
app.get('/api/players', async (req, res) => {
  try {
    const { search, country, limit = 20, offset = 0 } = req.query;
    let q = `SELECT p.*,t.name AS team_name,t.flag_emoji FROM players p LEFT JOIN teams t ON t.id=p.team_id WHERE p.is_active=TRUE`;
    const params = [];
    if (search) { params.push(`%${search}%`); q += ` AND p.display_name ILIKE $${params.length}`; }
    if (country) { params.push(country); q += ` AND p.country_code=$${params.length}`; }
    params.push(limit, offset);
    q += ` ORDER BY p.display_name LIMIT $${params.length-1} OFFSET $${params.length}`;
    const { rows } = await getPool().query(q, params);
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/players/:id', async (req, res) => {
  try {
    const { rows } = await getPool().query(
      `SELECT p.*,t.name AS team_name,t.flag_emoji FROM players p LEFT JOIN teams t ON t.id=p.team_id WHERE p.id=$1`,
      [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    const { rows: batting } = await getPool().query('SELECT * FROM player_batting_stats WHERE player_id=$1', [req.params.id]);
    const { rows: bowling } = await getPool().query('SELECT * FROM player_bowling_stats WHERE player_id=$1', [req.params.id]);
    res.json({ player: rows[0], batting_stats: batting, bowling_stats: bowling });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Articles ─────────────────────────────────────────────────
app.get('/api/articles', async (req, res) => {
  try {
    const { category, limit = 12, offset = 0 } = req.query;
    let q = `SELECT a.id,a.slug,a.title,a.excerpt,a.featured_image,a.published_at,a.view_count,
                    u.display_name AS author_name,c.name AS category_name,c.color AS category_color
             FROM articles a
             JOIN users u ON u.id=a.author_id
             LEFT JOIN categories c ON c.id=a.category_id
             WHERE a.status='published'`;
    const params = [];
    if (category) { params.push(category); q += ` AND c.slug=$${params.length}`; }
    params.push(limit, offset);
    q += ` ORDER BY a.published_at DESC LIMIT $${params.length-1} OFFSET $${params.length}`;
    const { rows } = await getPool().query(q, params);
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/articles/:slug', async (req, res) => {
  try {
    const { rows } = await getPool().query(`
      SELECT a.*,u.display_name AS author_name,c.name AS category_name
      FROM articles a
      JOIN users u ON u.id=a.author_id
      LEFT JOIN categories c ON c.id=a.category_id
      WHERE a.slug=$1 AND a.status='published'`, [req.params.slug]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    getPool().query('UPDATE articles SET view_count=view_count+1 WHERE id=$1', [rows[0].id]);
    res.json(rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Comments ─────────────────────────────────────────────────
app.get('/api/comments', async (req, res) => {
  try {
    const { article_id, limit = 20 } = req.query;
    const { rows } = await getPool().query(`
      SELECT c.*,u.display_name AS author_name,u.avatar_url AS author_avatar
      FROM comments c JOIN users u ON u.id=c.user_id
      WHERE c.article_id=$1 AND c.status='approved'
      ORDER BY c.created_at DESC LIMIT $2`, [article_id, limit]);
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/comments', auth, async (req, res) => {
  const { article_id, content } = req.body;
  if (!content?.trim()) return res.status(400).json({ error: 'Content required' });
  try {
    const { rows } = await getPool().query(
      `INSERT INTO comments (user_id,article_id,content,status) VALUES ($1,$2,$3,'approved') RETURNING *`,
      [req.user.id, article_id, content.trim()]);
    res.status(201).json(rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Quiz ─────────────────────────────────────────────────────
app.get('/api/quiz/questions', async (req, res) => {
  try {
    const { limit = 10 } = req.query;
    const { rows } = await getPool().query(
      `SELECT id,question,option_a,option_b,option_c,option_d,hint,difficulty,points
       FROM quiz_questions WHERE is_active=TRUE ORDER BY RANDOM() LIMIT $1`, [limit]);
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/quiz/leaderboard', async (req, res) => {
  try {
    const { rows } = await getPool().query(`
      SELECT l.*,u.display_name,u.country_code
      FROM quiz_leaderboard l JOIN users u ON u.id=l.user_id
      WHERE l.period='alltime'
      ORDER BY l.total_points DESC LIMIT 20`);
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Predictions ───────────────────────────────────────────────
app.post('/api/predictions/vote', auth, async (req, res) => {
  const { match_id, voted_for } = req.body;
  try {
    await getPool().query(
      `INSERT INTO prediction_votes (user_id,match_id,voted_for) VALUES ($1,$2,$3)
       ON CONFLICT (user_id,match_id) DO NOTHING`,
      [req.user.id, match_id, voted_for || null]);
    const { rows } = await getPool().query(
      `SELECT voted_for,COUNT(*) FROM prediction_votes WHERE match_id=$1 GROUP BY voted_for`,
      [match_id]);
    res.json({ success: true, counts: rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Newsletter ────────────────────────────────────────────────
app.post('/api/newsletter/subscribe', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });
  try {
    await getPool().query(
      `INSERT INTO newsletter_subscribers (email) VALUES ($1)
       ON CONFLICT (email) DO UPDATE SET is_active=TRUE`, [email]);
    res.json({ subscribed: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── History ───────────────────────────────────────────────────
app.get('/api/history/today', async (req, res) => {
  try {
    const now = new Date();
    const { rows } = await getPool().query(
      `SELECT * FROM history_events
       WHERE EXTRACT(MONTH FROM event_date)=$1 AND EXTRACT(DAY FROM event_date)=$2
       ORDER BY year DESC`,
      [now.getMonth() + 1, now.getDate()]);
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Start ─────────────────────────────────────────────────────
const PORT = process.env.PORT || 8080;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`CricPulse API running on port ${PORT}`);
});

module.exports = app;
