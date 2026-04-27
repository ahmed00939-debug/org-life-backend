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
app.use(express.json()); // عشان السيرفر يفهم الـ JSON
app.use(cors()); // عشان يسمح للفرونت اند (موبايل أو ويب) يكلمه
app.use(helmet()); // حماية إضافية للـ Headers

// منع السبام (Rate Limiting) - بحد أقصى 100 طلب كل ربع ساعة للـ IP الواحد
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 100,
    message: 'طلبات كتير جداً من الجهاز ده، استنى شوية وجرب تاني.'
});
app.use(limiter);

// 3. الاتصال بقاعدة بيانات Supabase عبر الـ API (ضد الحظر)
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_ANON_KEY;

if (!supabaseUrl || !supabaseKey) {
    console.error('❌ خطأ: بيانات سوبابيز (URL أو KEY) مش موجودة في ملف .env');
    process.exit(1);
}

const supabase = createClient(supabaseUrl, supabaseKey);

// اختبار الاتصال
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

// مسار الفحص (عشان تتأكد إن السيرفر شغال لو فتحته من المتصفح)
app.get('/', (req, res) => {
    res.json({ message: '🚀 سيرفر Org Life يعمل بنجاح!' });
});

// 🟢 مسار التسجيل (Register)
app.post('/api/register', async (req, res) => {
    try {
        const { full_name, email, password } = req.body;

        // التأكد من إدخال كل البيانات
        if (!full_name || !email || !password) {
            return res.status(400).json({ error: 'برجاء إدخال جميع البيانات (الاسم، الإيميل، الباسورد)' });
        }

        // تشفير الباسورد
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // حفظ المستخدم في قاعدة البيانات
        const { data, error } = await supabase
            .from('users')
            .insert([
                { full_name: full_name, email: email, password: hashedPassword }
            ])
            .select();

        // لو الإيميل متسجل قبل كدة أو فيه خطأ
        if (error) {
            if (error.code === '23505') {
                return res.status(400).json({ error: 'هذا البريد الإلكتروني مسجل بالفعل' });
            }
            throw error;
        }

        res.status(201).json({ 
            message: 'تم إنشاء الحساب بنجاح', 
            user: { id: data[0].id, full_name: data[0].full_name, email: data[0].email } // مش بنرجع الباسورد في الرد
        });

    } catch (err) {
        console.error('Register Error:', err.message);
        res.status(500).json({ error: 'حدث خطأ داخلي في السيرفر أثناء التسجيل' });
    }
});

// 🔵 مسار تسجيل الدخول (Login)
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'برجاء إدخال الإيميل والباسورد' });
        }

        // البحث عن المستخدم بالإيميل
        const { data: users, error } = await supabase
            .from('users')
            .select('*')
            .eq('email', email);

        if (error) throw error;

        // لو الإيميل مش موجود
        if (!users || users.length === 0) {
            return res.status(401).json({ error: 'البريد الإلكتروني أو كلمة المرور غير صحيحة' });
        }

        const user = users[0];

        // مقارنة الباسورد اللي دخل بالباسورد المتشفر في الداتا بيز
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(401).json({ error: 'البريد الإلكتروني أو كلمة المرور غير صحيحة' });
        }

        // عمل توكن (JWT) عشان المستخدم يفضل مسجل دخول
        const token = jwt.sign(
            { userId: user.id, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: '7d' } // التوكن صالح لمدة 7 أيام
        );

        res.status(200).json({ 
            message: 'تم تسجيل الدخول بنجاح', 
            token: token,
            user: { id: user.id, full_name: user.full_name, email: user.email }
        });

    } catch (err) {
        console.error('Login Error:', err.message);
        res.status(500).json({ error: 'حدث خطأ داخلي في السيرفر أثناء تسجيل الدخول' });
    }
});

// ==========================================
// 5. تشغيل السيرفر
// ==========================================
app.listen(port, () => {
    console.log(`=================================`);
    console.log(`🚀 السيرفر شغال على بورت: ${port}`);
    console.log(`🔗 الرابط المحلي: http://localhost:${port}`);
    console.log(`=================================`);
});