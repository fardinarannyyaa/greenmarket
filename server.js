const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = 3000;
const JWT_SECRET = 'greenmarket_secret_key_2025'; // change this in production

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public'))); // serves your HTML

// ===== DATABASE SETUP =====
const db = new Database('greenmarket.db');

// Create tables
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    phone TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'buyer',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    price INTEGER NOT NULL,
    unit TEXT NOT NULL,
    category TEXT NOT NULL,
    img TEXT,
    farmer TEXT,
    location TEXT,
    phone TEXT,
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    user_name TEXT,
    user_phone TEXT,
    items TEXT NOT NULL,
    total INTEGER NOT NULL,
    status TEXT DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS leads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    phone TEXT NOT NULL,
    district TEXT,
    interest TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// Seed some products if empty
const productCount = db.prepare('SELECT COUNT(*) as count FROM products').get();
if (productCount.count === 0) {
  const insertProduct = db.prepare(`
    INSERT INTO products (name, price, unit, category, img, farmer, location, phone, description)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  const seedProducts = [
    ['টমেটো', 60, 'কেজি', 'vegetables', 'https://images.unsplash.com/photo-1518977822534-7049a61ee0c2?w=400', 'আব্দুল মান্নান', 'পটুয়াখালী', '01712345678', 'তাজা দেশীয় টমেটো, কোনো রাসায়নিক ছাড়া।'],
    ['আলু', 35, 'কেজি', 'vegetables', 'https://images.unsplash.com/photo-1586201375761-83865001e31c?w=400', 'শফিকুল ইসলাম', 'নওগাঁ', '01898765432', 'উত্তরবঙ্গের বিখ্যাত আলু।'],
    ['আম', 120, 'কেজি', 'fruits', 'https://images.unsplash.com/photo-1553279768-865429fa0078?w=400', 'মরিয়ম বেগম', 'সিলেট', '01611223344', 'রাজশাহীর মিষ্টি আম।'],
    ['কাঁচা মরিচ', 80, 'কেজি', 'grains', 'https://images.unsplash.com/photo-1563565375-f3fdfdbefa83?w=400', 'রহিম উদ্দিন', 'বগুড়া', '01755667788', 'ঝাল কাঁচা মরিচ।'],
    ['ইলিশ মাছ', 800, 'কেজি', 'fish', 'https://images.unsplash.com/photo-1615141982883-c7ad0e69fd62?w=400', 'করিম মাঝি', 'বরিশাল', '01933445566', 'পদ্মার তাজা ইলিশ।'],
    ['কলা', 40, 'ডজন', 'fruits', 'https://images.unsplash.com/photo-1571771894821-ce9b6c11b08e?w=400', 'সালেহা বেগম', 'ময়মনসিংহ', '01844556677', 'সাগর কলা।'],
    ['পেঁয়াজ', 55, 'কেজি', 'grains', 'https://images.unsplash.com/photo-1618512496248-a07fe83aa8cb?w=400', 'জয়নাল আবেদীন', 'ফরিদপুর', '01977889900', 'দেশীয় পেঁয়াজ।'],
    ['দেশি মুরগি', 450, 'কেজি', 'fish', 'https://images.unsplash.com/photo-1548550023-2bdb3c5beed7?w=400', 'আনোয়ার হোসেন', 'কুমিল্লা', '01500112233', 'খাঁটি দেশি মুরগি।'],
  ];
  for (const p of seedProducts) insertProduct.run(...p);
  console.log('✅ Sample products added to database');
}

// ===== AUTH MIDDLEWARE =====
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'লগইন প্রয়োজন' });
  try {
    const user = jwt.verify(token, JWT_SECRET);
    req.user = user;
    next();
  } catch {
    return res.status(403).json({ error: 'টোকেন বৈধ নয়' });
  }
}

// ===== AUTH ROUTES =====

// Register
app.post('/api/register', (req, res) => {
  const { name, phone, password } = req.body;
  if (!name || !phone || !password)
    return res.status(400).json({ error: 'সব তথ্য পূরণ করুন' });

  const existing = db.prepare('SELECT id FROM users WHERE phone = ?').get(phone);
  if (existing)
    return res.status(409).json({ error: 'এই নম্বর দিয়ে আগেই নিবন্ধন হয়েছে' });

  const hashed = bcrypt.hashSync(password, 10);
  const result = db.prepare('INSERT INTO users (name, phone, password) VALUES (?, ?, ?)').run(name, phone, hashed);

  const token = jwt.sign({ id: result.lastInsertRowid, name, phone }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ success: true, token, user: { id: result.lastInsertRowid, name, phone } });
});

// Login
app.post('/api/login', (req, res) => {
  const { phone, password } = req.body;
  if (!phone || !password)
    return res.status(400).json({ error: 'নম্বর ও পাসওয়ার্ড দিন' });

  const user = db.prepare('SELECT * FROM users WHERE phone = ?').get(phone);
  if (!user || !bcrypt.compareSync(password, user.password))
    return res.status(401).json({ error: 'ভুল নম্বর বা পাসওয়ার্ড' });

  const token = jwt.sign({ id: user.id, name: user.name, phone: user.phone }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ success: true, token, user: { id: user.id, name: user.name, phone: user.phone } });
});

// ===== PRODUCT ROUTES =====

// Get all products (or filter by category)
app.get('/api/products', (req, res) => {
  const { category } = req.query;
  let products;
  if (category && category !== 'all') {
    products = db.prepare('SELECT * FROM products WHERE category = ? ORDER BY created_at DESC').all(category);
  } else {
    products = db.prepare('SELECT * FROM products ORDER BY created_at DESC').all();
  }
  res.json(products);
});

// Get single product
app.get('/api/products/:id', (req, res) => {
  const product = db.prepare('SELECT * FROM products WHERE id = ?').get(req.params.id);
  if (!product) return res.status(404).json({ error: 'পণ্য পাওয়া যায়নি' });
  res.json(product);
});

// ===== ORDER ROUTES =====

// Place order (requires login)
app.post('/api/orders', authenticateToken, (req, res) => {
  const { items, total } = req.body;
  if (!items || !total)
    return res.status(400).json({ error: 'অর্ডারের তথ্য অসম্পূর্ণ' });

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  const result = db.prepare(
    'INSERT INTO orders (user_id, user_name, user_phone, items, total) VALUES (?, ?, ?, ?, ?)'
  ).run(req.user.id, user.name, user.phone, JSON.stringify(items), total);

  res.json({ success: true, orderId: result.lastInsertRowid, message: 'অর্ডার সফল হয়েছে!' });
});

// Get my orders (requires login)
app.get('/api/orders/my', authenticateToken, (req, res) => {
  const orders = db.prepare('SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC').all(req.user.id);
  const parsed = orders.map(o => ({ ...o, items: JSON.parse(o.items) }));
  res.json(parsed);
});

// ===== LEAD FORM =====
app.post('/api/leads', (req, res) => {
  const { name, phone, district, interest } = req.body;
  if (!name || !phone)
    return res.status(400).json({ error: 'নাম ও নম্বর আবশ্যক' });

  db.prepare('INSERT INTO leads (name, phone, district, interest) VALUES (?, ?, ?, ?)').run(name, phone, district, interest);
  res.json({ success: true, message: 'তথ্য সংরক্ষিত হয়েছে!' });
});

// ===== SERVE FRONTEND =====
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`\n🌿 Green Market Server চালু আছে!`);
  console.log(`👉 ব্রাউজারে খুলুন: http://localhost:${PORT}`);
  console.log(`📦 Database: greenmarket.db\n`);
});
