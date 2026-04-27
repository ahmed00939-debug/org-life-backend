require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');

// 1. إعداد السيرفر
const app = express();
const port = process.env.PORT || 3000;

// 2. إعدادات الحماية والـ Middleware
app.use(express.json()); 
app.use(cors()); 
app.use(helmet()); 

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 100,
    message: 'طلبات كتير جداً من الجهاز ده، استنى شوية وجرب تاني.'
});
app.use(limiter);

// 3. الاتصال بقاعدة بيانات Supabase
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_ANON_KEY;

if (!supabaseUrl || !supabaseKey) {
    console.error('❌ خطأ: بيانات سوبابيز مش موجودة في ملف .env');
    process.exit(1);
}

const supabase = createClient(supabaseUrl, supabaseKey);

// اختبار الاتصال عند التشغيل
async function testConnection() {
    console.log("⏳ جاري الاتصال بسوبابيز...");
    const { error } = await supabase.from('users').select('*').limit(1);
    if (error && error.code !== '42P01') { 
        console.error('❌ عطل في الاتصال:', error.message);
    } else {
        console.log('✅ تم الاتصال بـ Supabase بنجاح! 🚀');
    }
}
testConnection();

// ==========================================
// 4. مسارات السيرفر (Routes)
// ==========================================

app.get('/', (req, res) => {
    res.json({ message: '🚀 سيرفر Org Life يعمل بنجاح!' });
});

// 🟢 مسار التسجيل (Register)
app.post('/api/register', async (req, res) => {
    try {
        const { full_name, user_email, password } = req.body;

        if (!full_name || !user_email || !password) {
            return res.status(400).json({ error: 'برجاء إدخال جميع البيانات (الاسم، user_email، الباسورد)' });
        }

        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        const { data, error } = await supabase
            .from('users')
            .insert([
                { full_name: full_name, user_email: user_email, password: hashedPassword }
            ])
            .select();

        if (error) {
            if (error.code === '23505') {
                return res.status(400).json({ error: 'هذا البريد الإلكتروني مسجل بالفعل' });
            }
            throw error;
        }

        res.status(201).json({ 
            message: 'تم إنشاء الحساب بنجاح', 
            user: { id: data[0].id, full_name: data[0].full_name, user_email: data[0].user_email }
        });

    } catch (err) {
        console.error('Register Error:', err.message);
        res.status(500).json({ error: 'حدث خطأ داخلي في السيرفر أثناء التسجيل' });
    }
});

// 🔵 مسار تسجيل الدخول (Login)
app.post('/api/login', async (req, res) => {
    try {
        const { user_email, password } = req.body;

        if (!user_email || !password) {
            return res.status(400).json({ error: 'برجاء إدخال الـ user_email والباسورد' });
        }

        const { data: users, error } = await supabase
            .from('users')
            .select('*')
            .eq('user_email', user_email);

        if (error) throw error;

        if (!users || users.length === 0) {
            return res.status(401).json({ error: 'البريد الإلكتروني أو كلمة المرور غير صحيحة' });
        }

        const user = users[0];
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(401).json({ error: 'البريد الإلكتروني أو كلمة المرور غير صحيحة' });
        }

        const token = jwt.sign(
            { userId: user.id, user_email: user.user_email },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.status(200).json({ 
            message: 'تم تسجيل الدخول بنجاح', 
            token: token,
            user: { id: user.id, full_name: user.full_name, user_email: user.user_email }
        });

    } catch (err) {
        console.error('Login Error:', err.message);
        res.status(500).json({ error: 'حدث خطأ داخلي في السيرفر أثناء تسجيل الدخول' });
    }
});

// ==========================================
// 5. تشغيل السيرفر
// ==========================================
if (process.env.NODE_ENV !== 'production') {
    app.listen(port, () => {
        console.log(`=================================`);
        console.log(`🚀 السيرفر شغال على بورت: ${port}`);
        console.log(`🔗 http://localhost:${port}`);
        console.log(`=================================`);
    });
}

module.exports = app;