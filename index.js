require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const port = process.env.PORT || 3000;

// 1. إعدادات الحماية والـ Middleware
app.use(express.json());
app.use(cors());
app.use(helmet());

// 2. الربط بـ Supabase
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_ANON_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

// دالة فحص الاتصال (عشان تطمن أول ما تشغل)
async function testConnection() {
    try {
        const { error } = await supabase.from('users').select('count', { count: 'exact', head: true });
        if (error) {
            console.log("❌ مشكلة في بيانات Supabase: ", error.message);
        } else {
            console.log("✅ تم الاتصال بـ Supabase بنجاح! 🚀");
        }
    } catch (err) {
        console.log("❌ تعذر الوصول لسيرفر Supabase.. تأكد من الإنترنت.");
    }
}

// 3. المسارات (End Points)

// فحص السيرفر
app.get('/', (req, res) => {
    res.json({ message: "🚀 Org Life Server is Running!" });
});

// 🟢 مسار التسجيل (Register)
app.post('/api/register', async (req, res) => {
    try {
        const { user_fullname, user_email, password } = req.body;

        if (!user_fullname || !user_email || !password) {
            return res.status(400).json({ error: "برجاء إدخال (user_fullname, user_email, password)" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const { data, error } = await supabase
            .from('users')
            .insert([{ 
                user_fullname: user_fullname, 
                user_email: user_email, 
                password: hashedPassword 
            }])
            .select();

        if (error) {
            if (error.code === '23505') return res.status(400).json({ error: "الإيميل ده موجود قبل كدة" });
            return res.status(400).json({ error: error.message });
        }

        res.status(201).json({ 
            message: "تم إنشاء الحساب بنجاح ✅", 
            user: { id: data[0].user_id, name: data[0].user_fullname, email: data[0].user_email } 
        });

    } catch (err) {
        res.status(500).json({ error: "خطأ داخلي في السيرفر" });
    }
});

// 🔵 مسار تسجيل الدخول (Login)
app.post('/api/login', async (req, res) => {
    try {
        const { user_email, password } = req.body;

        if (!user_email || !password) {
            return res.status(400).json({ error: "برجاء إدخال الإيميل والباسورد" });
        }

        const { data: users, error } = await supabase
            .from('users')
            .select('*')
            .eq('user_email', user_email);

        if (error || !users || users.length === 0) {
            return res.status(401).json({ error: "بيانات الدخول غير صحيحة" });
        }

        const user = users[0];
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(401).json({ error: "بيانات الدخول غير صحيحة" });
        }

        // إنشاء التوكن
        const token = jwt.sign(
            { userId: user.user_id, email: user.user_email },
            process.env.JWT_SECRET || 'OrgLife_2026_Secret',
            { expiresIn: '7d' }
        );

        res.status(200).json({ 
            message: "تم تسجيل الدخول بنجاح 👋", 
            token,
            user: { id: user.user_id, name: user.user_fullname, email: user.user_email }
        });

    } catch (err) {
        res.status(500).json({ error: "خطأ في السيرفر" });
    }
});

// 4. تشغيل السيرفر
app.listen(port, () => {
    console.log(`=================================`);
    console.log(`🚀 السيرفر شغال على بورت: ${port}`);
    console.log(`=================================`);
    testConnection(); // بيفحص الاتصال بعد ما السيرفر يقوم مباشرة
});

module.exports = app;