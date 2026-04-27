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

// Middleware
app.use(express.json()); 
app.use(cors()); 
app.use(helmet()); 

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 100,
    message: 'طلبات كتير جداً، جرب تاني كمان شوية.'
});
app.use(limiter);

// Supabase Connection
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_ANON_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

// Routes
app.get('/', (req, res) => {
    res.json({ message: '🚀 سيرفر Org Life يعمل بنجاح!' });
});

// 🟢 مسار التسجيل (Register) - معدل ليطابق صورة الداتا بيز
app.post('/api/register', async (req, res) => {
    try {
        const { full_name, user_email, password } = req.body;

        if (!full_name || !user_email || !password) {
            return res.status(400).json({ error: 'برجاء إدخال جميع البيانات' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const { data, error } = await supabase
            .from('users')
            .insert([
                { 
                    user_fullname: full_name, // مطابق للصورة
                    user_email: user_email,   // مطابق للصورة
                    password: hashedPassword 
                }
            ])
            .select();

        if (error) {
            if (error.code === '23505') return res.status(400).json({ error: 'الإيميل ده موجود قبل كدة' });
            throw error;
        }

        res.status(201).json({ 
            message: 'تم إنشاء الحساب بنجاح', 
            user: { id: data[0].user_id, name: data[0].user_fullname, email: data[0].user_email }
        });

    } catch (err) {
        console.error('Register Error:', err.message);
        res.status(500).json({ error: 'حدث خطأ في السيرفر' });
    }
});

// 🔵 مسار تسجيل الدخول (Login)
app.post('/api/login', async (req, res) => {
    try {
        const { user_email, password } = req.body;

        const { data: users, error } = await supabase
            .from('users')
            .select('*')
            .eq('user_email', user_email);

        if (error || !users || users.length === 0) {
            return res.status(401).json({ error: 'بيانات الدخول غير صحيحة' });
        }

        const user = users[0];
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) return res.status(401).json({ error: 'بيانات الدخول غير صحيحة' });

        const token = jwt.sign(
            { userId: user.user_id, email: user.user_email },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.status(200).json({ 
            message: 'تم تسجيل الدخول بنجاح', 
            token,
            user: { id: user.user_id, name: user.user_fullname, email: user.user_email }
        });

    } catch (err) {
        res.status(500).json({ error: 'حدث خطأ في السيرفر' });
    }
});

// Start Server
if (process.env.NODE_ENV !== 'production') {
    app.listen(port, () => {
        console.log(`🚀 السيرفر شغال على بورت: ${port}`);
    });
}

module.exports = app;