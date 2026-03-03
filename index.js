require('dotenv').config(); // تحميل الأسرار من ملف .env
const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const bcrypt = require('bcrypt'); // لتشفير الباسوردات
const jwt = require('jsonwebtoken'); // لعمل تذاكر دخول آمنة

const app = express();
const port = process.env.PORT || 3000; // استخدام PORT الخاص بـ Vercel أو 3000 محلياً
const JWT_SECRET = "ORG_LIFE_SUPER_SECRET_KEY_2026"; // مفتاح لتوقيع التذاكر

// --- [ الإعدادات الأساسية ] ---
app.use(cors());
app.use(express.json());

// --- [ إعداد الاتصال بـ Supabase ] ---
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// تأكيد الاتصال
pool.connect((err, client, release) => {
    if (err) return console.error('❌ خطأ في الاتصال:', err.stack);
    console.log('✅ تم الاتصال بـ Supabase بنجاح (نظام احترافي)!');
    release();
});

// --- [ المسارات - Routes ] ---

// مسار تجريبي للتأكد إن Vercel شغال
app.get('/', (req, res) => {
    res.send('Server is running perfectly on Vercel! 🚀');
});

// 1. تسجيل فلاح جديد مع تشفير باسورده (Sign Up)
app.post('/api/register', async (req, res) => {
    const { full_name, email, password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await pool.query(
            'INSERT INTO farmer (farmer_fullname, farmer_email, farmer_password) VALUES ($1, $2, $3) RETURNING farmer_id, farmer_fullname, farmer_email',
            [full_name, email, hashedPassword]
        );
        res.status(201).json({ message: "تم التسجيل بنجاح", user: result.rows[0] });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "الإيميل موجود بالفعل أو البيانات ناقصة" });
    }
});

// 2. تسجيل الدخول الآمن (Login)
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM farmer WHERE farmer_email = $1', [email]);
        if (result.rows.length === 0) {
            return res.status(401).json({ error: "المستخدم غير موجود" });
        }
        const user = result.rows[0];
        const isMatch = await bcrypt.compare(password, user.farmer_password);
        if (isMatch) {
            const token = jwt.sign({ id: user.farmer_id }, JWT_SECRET, { expiresIn: '24h' });
            res.status(200).json({
                message: "تم الدخول بنجاح",
                token: token,
                user: { id: user.farmer_id, name: user.farmer_fullname }
            });
        } else {
            res.status(401).json({ error: "الباسورد غلط" });
        }
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "خطأ في السيرفر" });
    }
});

// 3. جلب كل الفلاحين (للتجربة)
app.get('/api/farmers', async (req, res) => {
    try {
        const result = await pool.query('SELECT farmer_id, farmer_fullname, farmer_email FROM farmer');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: "خطأ في جلب البيانات" });
    }
});

// --- [ التعديل الهام لـ Vercel ] ---
// هذا الجزء يسمح للسيرفر بالعمل محلياً ولا يعطل Vercel
if (process.env.NODE_ENV !== 'production') {
    app.listen(port, () => {
        console.log(`🚀 السيرفر شغال محلياً على: http://localhost:${port}`);
    });
}

// تصدير app لـ Vercel
module.exports = app;