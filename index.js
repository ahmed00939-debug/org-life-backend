require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
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
        // 1. زودنا user_phone_number في الاستلام من req.body
        const { user_fullname, user_email, password, user_phone_number } = req.body;
        
        // 2. التحقق من وجود رقم التليفون
        if (!user_fullname || !user_email || !password || !user_phone_number) {
            return res.status(400).json({ error: "الاسم والإيميل والباسورد ورقم التليفون مطلوبين" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        // 3. إضافة user_phone_number في جملة الـ insert
        const { data, error } = await supabase
            .from('users')
            .insert([{ 
                user_fullname, 
                user_email, 
                user_password: hashedPassword, 
                user_phone_number // 👈 السطر الجديد
            }]) 
            .select();

        if (error) {
            if (error.code === '23505') return res.status(400).json({ error: "الإيميل مسجل مسبقاً" });
            throw error;
        }

        // 4. إرجاع رقم التليفون في الـ response
        res.status(201).json({ 
            message: "تم التسجيل بنجاح ✅", 
            user: { 
                id: data[0].user_id, 
                name: data[0].user_fullname, 
                email: data[0].user_email,
                phone: data[0].user_phone_number // 👈 إرجاعه للموبايل
            } 
        });
    } catch (err) { 
        console.error(err);
        res.status(500).json({ error: "خطأ في السيرفر" }); 
    }
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

        // 5. إرسال رقم التليفون مع بيانات المستخدم عند تسجيل الدخول
        res.json({ 
            token, 
            user: { 
                id: user.user_id, 
                name: user.user_fullname, 
                email: user.user_email,
                phone: user.user_phone_number // 👈 السطر الجديد
            } 
        });
    } catch (err) { res.status(500).json({ error: "خطأ في السيرفر" }); }
});


// ==========================================
// 🔑 مسارات استعادة كلمة المرور (Reset Password)
// ==========================================

// 1. طلب كود الاستعادة (Forgot Password - Demo Mode)
app.post('/api/forgot-password', async (req, res) => {
    try {
        const { user_email } = req.body;
        if (!user_email) return res.status(400).json({ error: "البريد الإلكتروني مطلوب" });

        // التأكد إن الإيميل موجود
        const { data: users, error: searchError } = await supabase
            .from('users')
            .select('*')
            .eq('user_email', user_email);

        if (searchError || !users.length) {
            return res.status(404).json({ error: "البريد الإلكتروني غير مسجل لدينا" });
        }

        // توليد كود OTP من 6 أرقام
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        // الكود صالح لمدة 15 دقيقة
        const expires = new Date(Date.now() + 15 * 60000).toISOString();

        // حفظ الكود في الداتابيز
        const { error: updateError } = await supabase
            .from('users')
            .update({ 
                reset_password_token: otp, 
                reset_password_expires: expires 
            })
            .eq('user_email', user_email);

        if (updateError) throw updateError;

        // 🌟 إرجاع الكود للموبايل لعرضه في شاشة المناقشة
        res.status(200).json({ 
            message: "تم طلب الاستعادة بنجاح",
            otp: otp 
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "حدث خطأ أثناء طلب الاستعادة" });
    }
});

// 2. تعيين كلمة المرور الجديدة (Reset Password)
app.post('/api/reset-password', async (req, res) => {
    try {
        const { user_email, otp, new_password } = req.body;
        
        if (!user_email || !otp || !new_password) {
            return res.status(400).json({ error: "جميع الحقول مطلوبة" });
        }

        // جلب المستخدم والتأكد من الكود
        const { data: users, error } = await supabase
            .from('users')
            .select('*')
            .eq('user_email', user_email)
            .eq('reset_password_token', otp);

        if (error || !users.length) {
            return res.status(400).json({ error: "الكود غير صحيح أو انتهت صلاحيته" });
        }

        const user = users[0];

        // التأكد إن الكود منتهيش
        if (new Date(user.reset_password_expires) < new Date()) {
            return res.status(400).json({ error: "انتهت صلاحية الكود، برجاء طلب كود جديد" });
        }

        // تشفير الباسورد الجديد
        const hashedPassword = await bcrypt.hash(new_password, 10);

        // تحديث الباسورد ومسح التوكن
        const { error: updateError } = await supabase
            .from('users')
            .update({ 
                user_password: hashedPassword,
                reset_password_token: null,
                reset_password_expires: null
            })
            .eq('user_email', user_email);

        if (updateError) throw updateError;

        res.status(200).json({ message: "تم تغيير كلمة المرور بنجاح ✅" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "حدث خطأ أثناء تغيير كلمة المرور" });
    }
});
// ==========================================
// 📦 2. مسارات المنتجات (Public) - نسخة مدمجة ومترتبة
// ==========================================

app.get('/api/products', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('products')
            .select('*, product_category(category_name)') // بيجيب بيانات المنتج + اسم القسم
            .order('product_id', { ascending: true });   // الترتيب التصاعدي اللي هيظبط شكل الموبايل

        if (error) throw error;
        res.status(200).json(data);
    } catch (err) { 
        res.status(500).json({ error: "خطأ في جلب المنتجات", message: err.message }); 
    }
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

app.post('/api/orders', authenticateToken, async (req, res) => {
    try {
        // 1. استلام البيانات من الموبايل (إجمالي السعر، العنوان، وقائمة المنتجات)
        const { order_delivery_address, order_total_price, items } = req.body;
        const user_id = req.user.userId; // بنجيبه من التوكن (أمان 100%)

        // 2. إدخال الفاتورة الأساسية في جدول orders
        const { data: orderData, error: orderError } = await supabase
            .from('orders')
            .insert([{ 
                user_id: user_id,
                order_delivery_address: order_delivery_address,
                order_total_price: order_total_price,
                order_status: 'pending' 
            }])
            .select();

        if (orderError) throw orderError;

        const newOrderId = orderData[0].order_id;

        // 3. إدخال تفاصيل المنتجات في جدول order_details (لو السلة فيها منتجات)
        if (items && items.length > 0) {
            const orderDetailsToInsert = items.map(item => ({
                order_id: newOrderId,
                product_id: item.product_id,
                od_quantity: item.quantity,
                od_price_at_purchase: item.price,
                od_subtotal: item.quantity * item.price // حساب الإجمالي الفرعي
            }));

            const { error: detailsError } = await supabase
                .from('order_details')
                .insert(orderDetailsToInsert);

            if (detailsError) throw detailsError;
        }

        // 4. الرد بنجاح على الموبايل
        res.status(201).json({ 
            message: "تم إنشاء الطلب وتفاصيله بنجاح ✅", 
            order_id: newOrderId 
        });

    } catch (err) { 
        res.status(500).json({ error: "خطأ في إنشاء الطلب", details: err.message }); 
    }
});

// ==========================================
// 📦 مسار جلب طلباتي (My Orders)
// ==========================================
app.get('/api/my-orders', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;

        // السطر ده سحر Supabase: بيجيب الطلب + تفاصيله + بيانات المنتجات اللي جوه التفاصيل!
        const { data, error } = await supabase
            .from('orders')
            .select(`
                *,
                order_details (
                    *,
                    products (*)
                )
            `)
            .eq('user_id', userId)
            .order('order_date', { ascending: false });

        if (error) throw error;
        
        res.status(200).json(data);
    } catch (err) {
        console.error("Error fetching my orders:", err);
        res.status(500).json({ error: "حدث خطأ أثناء جلب الطلبات" });
    }
});
// ==========================================
// 🧮 5. مسارات حسابات العلف - Calculations (Protected)
// ==========================================

// حفظ عملية حساب جديدة (بعد ما اليوزر يدوس Calculate)
app.post('/api/calculations', authenticateToken, async (req, res) => {
    try {
        const { corn_amount, wheat_amount, soybean_amount, feeding_frequency } = req.body;

        const { data, error } = await supabase
            .from('feeding_calculations')
            .insert([{ 
                user_id: req.user.userId, 
                corn_amount: corn_amount || 0, 
                wheat_amount: wheat_amount || 0, // شيلنا الكالسيوم وحطينا القمح
                soybean_amount: soybean_amount || 0,
                feeding_frequency: feeding_frequency || 1
            }])
            .select();

        if (error) throw error;
        res.status(201).json({ message: "تم حفظ العملية بنجاح ✅", calculation: data[0] });
    } catch (err) { 
        console.error("Save Calculation Error:", err);
        res.status(500).json({ error: "خطأ في حفظ العملية الحسابية" }); 
    }
});

// جلب سجل العمليات السابقة للمستخدم (عشان تظهر في History)
app.get('/api/calculations', authenticateToken, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('feeding_calculations')
            .select('*')
            .eq('user_id', req.user.userId)
            .order('created_at', { ascending: false }); // الترتيب من الأحدث للأقدم

        if (error) throw error;
        res.status(200).json(data);
    } catch (err) { 
        console.error("Fetch Calculations Error:", err);
        res.status(500).json({ error: "خطأ في جلب سجل العمليات" }); 
    }
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

// المتغير ده Vercel بتضيفه تلقائي من عندها، 
// فلو مش موجود (يعني إحنا على جهازك)، شغل السيرفر عادي.
if (!process.env.VERCEL) {
    startServer();
}

module.exports = app;

// ==========================================
// 🤖 مسار الذكاء الاصطناعي (AI Chat)
// ==========================================
const { GoogleGenAI } = require('@google/generative-ai');

app.post('/api/ai-chat', authenticateToken, async (req, res) => {
    try {
        const { message } = req.body;
        const userId = req.user.userId; // بنجيب الـ ID بتاع اليوزر من التوكن

        if (!message) {
            return res.status(400).json({ error: "الرسالة مطلوبة" });
        }

        // 1. جلب بيانات المستخدم من Supabase
        // بنجيب القطعان
        const { data: flocks } = await supabase
            .from('flocks')
            .select('*')
            .eq('user_id', userId);

        // بنجيب آخر حسابات العلف
        const { data: calculations } = await supabase
            .from('feeding_calculations')
            .select('*')
            .eq('user_id', userId)
            .order('created_at', { ascending: false })
            .limit(5);

        // بنجيب آخر طلبات الشراء
        const { data: orders } = await supabase
            .from('orders')
            .select('order_total_price, order_status, order_delivery_address')
            .eq('user_id', userId)
            .order('order_date', { ascending: false })
            .limit(5);

        // 2. تجهيز "عقل" الذكاء الاصطناعي (الـ Prompt)
        const contextPrompt = `
أنت خبير تغذية دواجن ومساعد ذكي مدمج في تطبيق لإدارة المزارع وتقليل تكلفة الأعلاف.
مهمتك: الإجابة على سؤال المستخدم وتقديم نصائح علمية وعملية لتوفير العلف بناءً على بياناته الحقيقية أدناه.

بيانات المستخدم الحالية من قاعدة البيانات:
- القطعان التي يمتلكها: ${JSON.stringify(flocks || [])}
- عمليات حساب العلف الأخيرة: ${JSON.stringify(calculations || [])}
- طلبات الشراء الأخيرة للمكونات: ${JSON.stringify(orders || [])}

سؤال المستخدم: "${message}"

تعليمات هامة لك:
1. أجب باللغة العربية بأسلوب احترافي وودود.
2. استخدم الأرقام والبيانات المذكورة أعلاه لتقديم حلول مخصصة له (مثل نسبة الذرة أو الصويا).
3. لا تقترح حلولاً خيالية، بل بناءً على مكونات العلف المتاحة (ذرة، صويا، قمح، إلخ).
`;

        // 3. الاتصال بـ Gemini
        const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });
        const model = ai.getGenerativeModel({ model: "gemini-2.5-flash" });

        const result = await model.generateContent(contextPrompt);
        const aiReply = result.response.text();

        // 4. إرسال الرد للموبايل
        res.status(200).json({ reply: aiReply });

    } catch (err) {
        console.error("AI Chat Error:", err);
        res.status(500).json({ error: "حدث خطأ أثناء معالجة طلب الذكاء الاصطناعي" });
    }
});