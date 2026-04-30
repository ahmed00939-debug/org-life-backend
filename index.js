require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());
app.use(cors());
app.use(helmet());

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_ANON_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

// ==========================================
// 🛡️ Middleware: حارس الأمن (للتأكد من تسجيل الدخول)
// ==========================================
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: "غير مصرح لك بالدخول، برجاء تسجيل الدخول أولاً." });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: "التوكن غير صالح أو انتهت صلاحيته." });
        req.user = user; 
        next();
    });
};

// ==========================================
// 🟢 1. مسارات المستخدمين (Auth)
// ==========================================

// التسجيل
app.post('/api/register', async (req, res) => {
    try {
        const { user_fullname, user_email, password } = req.body;
        if (!user_fullname || !user_email || !password) {
            return res.status(400).json({ error: "الاسم والإيميل والباسورد مطلوبين" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const { data, error } = await supabase
            .from('users')
            .insert([{ user_fullname, user_email, user_password: hashedPassword }]) // حسب جدولك الجديد
            .select();

        if (error) {
            if (error.code === '23505') return res.status(400).json({ error: "الإيميل مسجل مسبقاً" });
            throw error;
        }
        res.status(201).json({ message: "تم التسجيل بنجاح ✅", user: { id: data[0].user_id, name: data[0].user_fullname, email: data[0].user_email } });
    } catch (err) { res.status(500).json({ error: "خطأ في السيرفر" }); }
});

// تسجيل الدخول
app.post('/api/login', async (req, res) => {
    try {
        const { user_email, password } = req.body;
        const { data: users, error } = await supabase.from('users').select('*').eq('user_email', user_email);

        if (error || !users.length) return res.status(401).json({ error: "بيانات الدخول غير صحيحة" });

        const user = users[0];
        const isMatch = await bcrypt.compare(password, user.user_password);
        if (!isMatch) return res.status(401).json({ error: "بيانات الدخول غير صحيحة" });

        const token = jwt.sign({ userId: user.user_id }, process.env.JWT_SECRET, { expiresIn: '7d' });
        res.json({ token, user: { id: user.user_id, name: user.user_fullname, email: user.user_email } });
    } catch (err) { res.status(500).json({ error: "خطأ في السيرفر" }); }
});

// ==========================================
// 📦 2. مسارات المنتجات (Public)
// ==========================================

// جلب كل المنتجات
app.get('/api/products', async (req, res) => {
    try {
        const { data, error } = await supabase.from('products').select('*, product_category(category_name)');
        if (error) throw error;
        res.status(200).json(data);
    } catch (err) { res.status(500).json({ error: "خطأ في جلب المنتجات" }); }
});

// ==========================================
// 🐓 3. مسارات القطعان (Protected)
// ==========================================

// إضافة قطيع
app.post('/api/flocks', authenticateToken, async (req, res) => {
    try {
        const { flock_animaltype, flock_quantity } = req.body;
        if (!flock_animaltype || !flock_quantity) return res.status(400).json({ error: "نوع القطيع والكمية مطلوبين" });

        const { data, error } = await supabase
            .from('flocks')
            .insert([{ flock_animaltype, flock_quantity, user_id: req.user.userId }])
            .select();

        if (error) throw error;
        res.status(201).json({ message: "تم إضافة القطيع ✅", flock: data[0] });
    } catch (err) { res.status(500).json({ error: "خطأ داخلي" }); }
});

// جلب قطعان المستخدم فقط
app.get('/api/flocks', authenticateToken, async (req, res) => {
    try {
        const { data, error } = await supabase.from('flocks').select('*').eq('user_id', req.user.userId);
        if (error) throw error;
        res.status(200).json(data);
    } catch (err) { res.status(500).json({ error: "خطأ في جلب البيانات" }); }
});

// ==========================================
// 🛒 4. مسارات الطلبات - Orders (Protected)
// ==========================================

// إنشاء طلب جديد
app.post('/api/orders', authenticateToken, async (req, res) => {
    try {
        const { order_delivery_address } = req.body;
        
        const { data, error } = await supabase
            .from('orders')
            .insert([{ order_delivery_address, user_id: req.user.userId }])
            .select();

        if (error) throw error;
        res.status(201).json({ message: "تم إنشاء الطلب ✅", order: data[0] });
    } catch (err) { res.status(500).json({ error: "خطأ في إنشاء الطلب" }); }
});

// ==========================================
// 🚀 تشغيل وفحص السيرفر
// ==========================================
async function startServer() {
    console.log("====================================");
    console.log("⏳ جاري الاتصال بـ Supabase...");
    
    try {
        const { error } = await supabase.from('users').select('count', { count: 'exact', head: true });
        if (error) throw error;
        console.log("✅ تم الاتصال بـ Supabase بنجاح! 🚀");
    } catch (err) {
        console.log("❌ فشل الاتصال بقاعدة البيانات. تأكد من المفاتيح والإنترنت.");
    }

    app.listen(port, () => {
        console.log(`🚀 السيرفر شغال على بورت: ${port}`);
        console.log("====================================");
    });
}

startServer();
module.exports = app;