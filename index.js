require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const port = process.env.PORT || 3000;

// 1. Middleware الطبقات الدفاعية
app.use(express.json()); 
app.use(cors()); 
app.use(helmet()); 

// تحديد عدد الطلبات لحماية السيرفر من الهجمات
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 100,
    message: { error: 'طلبات كتير جداً، جرب تاني كمان ربع ساعة.' }
});
app.use('/api/', limiter);

// 2. إعداد Supabase
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_ANON_KEY;

if (!supabaseUrl || !supabaseKey) {
    console.error('❌ خطأ كارثي: مفاتيح Supabase مش موجودة في الـ .env');
    process.exit(1);
}

const supabase = createClient(supabaseUrl, supabaseKey);

// 3. المسارات (Routes)

// مسار فحص السيرفر
app.get('/', (req, res) => {
    res.json({ status: 'online', project: 'Org Life Backend', version: '1.0.0' });
});

// 🟢 مسار التسجيل (Register)
app.post('/api/register', async (req, res) => {
    try {
        const { user_fullname, user_email, password } = req.body;

        // Validation: التأكد إن البيانات كاملة ومنطقية
        if (!user_fullname || !user_email || !password) {
            return res.status(400).json({ error: 'كل الخانات مطلوبة (الاسم، الإيميل، الباسورد)' });
        }

        if (password.length < 6) {
            return res.status(400).json({ error: 'الباسورد لازم يكون على الأقل 6 حروف' });
        }

        // تشفير الباسورد
        const hashedPassword = await bcrypt.hash(password, 10);

        // إدخال البيانات في Supabase
        const { data, error } = await supabase
            .from('users')
            .insert([
                { 
                    user_fullname: user_fullname, 
                    user_email: user_email, 
                    password: hashedPassword 
                }
            ])
            .select();

        if (error) {
            if (error.code === '23505') return res.status(400).json({ error: 'هذا الإيميل مسجل مسبقاً' });
            throw error;
        }

        res.status(201).json({ 
            message: 'تم إنشاء الحساب بنجاح ✅', 
            user: { 
                id: data[0].user_id, 
                name: data[0].user_fullname, 
                email: data[0].user_email 
            }
        });

    } catch (err) {
        console.error('Register Error:', err.message);
        res.status(500).json({ error: 'حدث خطأ في السيرفر أثناء التسجيل' });
    }
});

// 🔵 مسار تسجيل الدخول (Login)
app.post('/api/login', async (req, res) => {
    try {
        const { user_email, password } = req.body;

        if (!user_email || !password) {
            return res.status(400).json({ error: 'دخل الإيميل والباسورد يا هندسة' });
        }

        // جلب المستخدم من الداتا بيز
        const { data: users, error } = await supabase
            .from('users')
            .select('*')
            .eq('user_email', user_email);

        if (error || !users || users.length === 0) {
            return res.status(401).json({ error: 'الإيميل أو الباسورد غلط' });
        }

        const user = users[0];

        // التحقق من الباسورد
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ error: 'الإيميل أو الباسورد غلط' });
        }

        // إنشاء التوكن JWT
        const token = jwt.sign(
            { userId: user.user_id, email: user.user_email },
            process.env.JWT_SECRET || 'secret_key_123',
            { expiresIn: '7d' }
        );

        res.status(200).json({ 
            message: 'أهلاً بك مرة أخرى! 👋', 
            token,
            user: { 
                id: user.user_id, 
                name: user.user_fullname, 
                email: user.user_email 
            }
        });

    } catch (err) {
        console.error('Login Error:', err.message);
        res.status(500).json({ error: 'حدث خطأ في السيرفر أثناء تسجيل الدخول' });
    }
});

// 4. تشغيل السيرفر (Production handling for Vercel)
if (process.env.NODE_ENV !== 'production') {
    app.listen(port, () => {
        console.log(`====================================`);
        console.log(`🚀 السيرفر شغال محلياً على بورت: ${port}`);
        console.log(`====================================`);
    });
}

module.exports = app;