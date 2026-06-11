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

app.get('/', (req, res) => {
    res.status(200).send('🚀 Org-Life API is Running Successfully!');
});

// ==========================================
// 🛡️ Middleware: حارس الأمن 
// ==========================================
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: "unauthorized" }); 

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: "invalid_token" }); 
        
        req.user = user; 

        supabase
            .from('users')
            .update({ last_active_at: new Date().toISOString() })
            .eq('user_id', user.userId)
            .then()
            .catch(e => console.log("Ignore DB update error")); 

        next();
    });
};

// ==========================================
// 🟢 1. مسارات المستخدمين (Auth)
// ==========================================

app.post('/api/register', async (req, res) => {
    try {
        const { user_fullname, user_email, password, user_phone_number } = req.body;
        
        if (!user_fullname || !user_email || !password || !user_phone_number) {
            return res.status(400).json({ error: "missing_fields" }); 
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const { data, error } = await supabase
            .from('users')
            .insert([{ user_fullname, user_email, user_password: hashedPassword, user_phone_number }]) 
            .select();

        if (error) {
            if (error.code === '23505') return res.status(400).json({ error: "email_exists" }); 
            throw error;
        }

        res.status(201).json({ 
            message: "register_success", 
            user: { id: data[0].user_id, name: data[0].user_fullname, email: data[0].user_email, phone: data[0].user_phone_number } 
        });
    } catch (err) { 
        res.status(500).json({ error: "server_error" }); 
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { user_email, password } = req.body;
        const { data: users, error } = await supabase.from('users').select('*').eq('user_email', user_email);

        if (error || !users.length) return res.status(401).json({ error: "invalid_credentials" }); 

        const user = users[0];
        const isMatch = await bcrypt.compare(password, user.user_password);
        if (!isMatch) return res.status(401).json({ error: "invalid_credentials" }); 

        const token = jwt.sign({ userId: user.user_id }, process.env.JWT_SECRET, { expiresIn: '7d' });

        res.json({ token, user: { id: user.user_id, name: user.user_fullname, email: user.user_email, phone: user.user_phone_number } });
    } catch (err) { res.status(500).json({ error: "server_error" }); }
});

app.post('/api/update-name', authenticateToken, async (req, res) => {
    try {
        const { new_name } = req.body;
        const userId = req.user.userId; 

        if (!new_name) {
            return res.status(400).json({ error: "الرجاء إرسال الاسم الجديد" });
        }

        const { data, error } = await supabase
            .from('users') 
            .update({ user_fullname: new_name }) 
            .eq('user_id', userId)
            .select();

        if (error) throw error;

        res.status(200).json({ message: "تم تحديث الاسم بنجاح ✅", data });
    } catch (err) {
        console.error("Update Name Error:", err.message);
        res.status(500).json({ error: "حدث خطأ أثناء التحديث", details: err.message });
    }
});

app.post('/api/forgot-password', async (req, res) => {
    try {
        const { user_email } = req.body;
        if (!user_email) return res.status(400).json({ error: "البريد الإلكتروني مطلوب" });

        const { data: users, error: searchError } = await supabase
            .from('users')
            .select('*')
            .eq('user_email', user_email);

        if (searchError || !users.length) {
            return res.status(404).json({ error: "البريد الإلكتروني غير مسجل لدينا" });
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const expires = new Date(Date.now() + 15 * 60000).toISOString();

        const { error: updateError } = await supabase
            .from('users')
            .update({ 
                reset_password_token: otp, 
                reset_password_expires: expires 
            })
            .eq('user_email', user_email);

        if (updateError) throw updateError;

        res.status(200).json({ 
            message: "تم طلب الاستعادة بنجاح، اكتب الكود المرفق في التطبيق",
            otp: otp 
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "حدث خطأ أثناء طلب الاستعادة" });
    }
});

app.post('/api/reset-password', async (req, res) => {
    try {
        const { user_email, otp, new_password } = req.body;
        
        if (!user_email || !otp || !new_password) {
            return res.status(400).json({ error: "جميع الحقول مطلوبة" });
        }

        const { data: users, error } = await supabase
            .from('users')
            .select('*')
            .eq('user_email', user_email)
            .eq('reset_password_token', otp);

        if (error || !users.length) {
            return res.status(400).json({ error: "الكود غير صحيح أو انتهت صلاحيته" });
        }

        const user = users[0];

        if (new Date(user.reset_password_expires) < new Date()) {
            return res.status(400).json({ error: "انتهت صلاحية الكود، برجاء طلب كود جديد" });
        }

        const hashedPassword = await bcrypt.hash(new_password, 10);

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
// 📦 2. مسارات المنتجات (Public)
// ==========================================
app.get('/api/products', async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('products')
            .select('*, product_category(category_name)')
            .order('product_id', { ascending: true });

        if (error) throw error;
        res.status(200).json(data);
    } catch (err) { 
        res.status(500).json({ error: "خطأ في جلب المنتجات", message: err.message }); 
    }
});

// ==========================================
// 🐓 3. مسارات القطعان - Flocks (Protected)
// ==========================================
app.post('/api/flocks', authenticateToken, async (req, res) => {
    const userId = req.user.userId || req.user.id; 
    const { flock_animaltype, flock_quantity, flock_arrivaldate } = req.body;
    
    if (!flock_animaltype || !flock_quantity) {
        return res.status(400).json({ error: "missing_fields" });
    }

    try {
        const { data, error } = await supabase
            .from('flocks')
            .insert([{ 
                user_id: userId, 
                flock_animaltype, 
                flock_quantity, 
                flock_arrivaldate: flock_arrivaldate || new Date().toISOString()
            }])
            .select();

        if (error) throw error;

        // تم مسح الإشعارات التلقائية من هنا ✅
        res.status(201).json({ message: "success", flock: data[0] });
    } catch (err) {
        console.error("Error adding flock:", err);
        res.status(500).json({ error: "server_error" });
    }
});

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
        const { order_delivery_address, order_total_price, items } = req.body;
        const user_id = req.user.userId;

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

        if (items && items.length > 0) {
            const orderDetailsToInsert = items.map(item => ({
                order_id: newOrderId,
                product_id: item.product_id,
                od_quantity: item.quantity,
                od_price_at_purchase: item.price,
                od_subtotal: item.quantity * item.price
            }));

            const { error: detailsError } = await supabase.from('order_details').insert(orderDetailsToInsert);
            if (detailsError) throw detailsError;
        }

        // تم مسح الإشعارات التلقائية من هنا ✅
        res.status(201).json({ message: "success", order_id: newOrderId });

    } catch (err) { 
        res.status(500).json({ error: "server_error", details: err.message }); 
    }
});

app.get('/api/my-orders', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        const { data, error } = await supabase
            .from('orders')
            .select(`*, order_details (*, products (*))`)
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
app.post('/api/calculations', authenticateToken, async (req, res) => {
    try {
        const { animal_type, animal_count, daily_savings, standard_feed, alfalfa_amount } = req.body;
        
        const { data, error } = await supabase
            .from('feeding_calculations')
            .insert([{ 
                user_id: req.user.userId, 
                animal_type: animal_type || 'laying_hens',
                animal_count: animal_count || 0,
                daily_savings_egp: daily_savings || 0,
                standard_feed_kg: standard_feed || 0,
                alternative_alfalfa_kg: alfalfa_amount || 0
            }])
            .select();

        if (error) throw error;

        // تم مسح الإشعارات التلقائية من هنا ✅
        res.status(201).json({ message: "calc_saved", calculation: data[0] }); 
    } catch (err) { 
        console.error("Save Calculation Error:", err);
        res.status(500).json({ error: "server_error" }); 
    }
});

app.get('/api/calculations', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId; 
        const { data, error } = await supabase
            .from('feeding_calculations')
            .select('*')
            .eq('user_id', userId)
            .order('created_at', { ascending: false }); 

        if (error) throw error;
        res.status(200).json(data);
    } catch (err) {
        console.error("Get Calculations Error:", err);
        res.status(500).json({ error: "server_error" });
    }
});

// ==========================================
// 🔔 6. مسارات الإشعارات - Notifications (Protected)
// ==========================================
app.get('/api/notifications', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        // لقط اللغة من الهيدر لمعرفة ما إذا كان التطبيق بالإنجليزي
        const langHeader = req.headers['accept-language'] || 'ar';
        const isArabic = !langHeader.toLowerCase().includes('en');

        // جلب الإشعارات الخاصة بالمستخدم أو الإعلانات العامة
        const { data, error } = await supabase
            .from('notifications')
            .select('*')
            .or(`user_id.eq.${userId},user_id.is.null`)
            .order('created_at', { ascending: false });

        if (error) throw error;

        // 🌟 تجهيز البيانات وترجمتها لتناسب الفلاتر مباشرة
        const formattedNotifications = data.map(notif => ({
            id: notif.id,
            type: notif.type,
            is_read: notif.is_read,
            created_at: notif.created_at,
            title: isArabic ? notif.title_ar : (notif.title_en || notif.title_ar),
            description: isArabic ? notif.body_ar : (notif.body_en || notif.body_ar)
        }));

        res.status(200).json(formattedNotifications);
    } catch (err) {
        console.error("Get Notifications Endpoint Error:", err);
        res.status(500).json({ error: "server_error" });
    }
});

app.put('/api/notifications/:id/read', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        const notifId = req.params.id;

        const { error } = await supabase
            .from('notifications')
            .update({ is_read: true })
            .eq('id', notifId)
            .eq('user_id', userId);

        if (error) throw error;
        res.status(200).json({ message: "notification_marked_as_read" });
    } catch (err) {
        console.error("Mark Notification Read Endpoint Error:", err);
        res.status(500).json({ error: "server_error" });
    }
});

// ==========================================
// 📢 مسار إضافة إعلانات/إشعارات من الإدارة (Admin)
// ==========================================
app.post('/api/admin/notifications', async (req, res) => {
    const { title_ar, title_en, body_ar, body_en, type, user_id } = req.body;
    
    try {
        const { data, error } = await supabase
            .from('notifications')
            .insert([{
                title_ar,
                title_en,
                body_ar,
                body_en,
                type: type || 'announcement',
                user_id: user_id || null // null تعني إرسال الإشعار لجميع المستخدمين
            }])
            .select();

        if (error) throw error;

        res.status(201).json({ message: "تم إرسال الإعلان بنجاح!", notification: data[0] });
    } catch (err) {
        console.error("Admin Notification Error:", err);
        res.status(500).json({ error: 'Server error' });
    }
});

// ==========================================
// 📜 7. مسار جلب سجل المحادثات (للفلاتر)
// ==========================================
app.get('/api/chat-history', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        const { data, error } = await supabase
            .from('chat_messages')
            .select('*')
            .eq('user_id', userId)
            .order('created_at', { ascending: true }); 

        if (error) throw error;
        res.status(200).json(data);
    } catch (err) {
        console.error("Error fetching history:", err);
        res.status(500).json({ error: "خطأ في جلب المحادثات السابقة" });
    }
});

// ==========================================
// 🧠 8. مساعد الذكاء الاصطناعي الشامل
// ==========================================
app.post('/api/ai-chat', authenticateToken, async (req, res) => {
    try {
        const { message, imageBase64 } = req.body; 
        const userId = req.user.userId; 
        
        const userText = (message && message.trim() !== "") ? message : (imageBase64 ? "حلل هذه الصورة بناءً على بياناتي" : "Hello");

        const { data: userProfile } = await supabase.from('users').select('user_fullname').eq('user_id', userId).maybeSingle();
        const userName = userProfile?.user_fullname ? userProfile.user_fullname.trim() : "يا هندسة";

        const { data: flocks } = await supabase.from('flocks').select('flock_animaltype, flock_quantity').eq('user_id', userId);
        const { data: calculations } = await supabase.from('feeding_calculations')
            .select('animal_type, animal_count, daily_savings_egp, standard_feed_kg, alternative_alfalfa_kg, created_at')
            .eq('user_id', userId)
            .order('created_at', { ascending: false })
            .limit(3);        

        const { data: recentOrders } = await supabase.from('orders')
            .select('order_total_price, order_status, order_date')
            .eq('user_id', userId)
            .order('order_date', { ascending: false })
            .limit(2);

        const flocksText = flocks && flocks.length > 0 ? JSON.stringify(flocks) : "لا توجد قطعان.";
        const calcText = calculations && calculations.length > 0 ? JSON.stringify(calculations) : "لا توجد حسابات.";
        const ordersText = recentOrders && recentOrders.length > 0 ? JSON.stringify(recentOrders) : "لا توجد طلبات سابقة.";

        const systemInstruction = `You are "Org-Life AI Assistant", an expert agricultural and animal feeding advisor.
🎯 CRITICAL LANGUAGE & NAME RULES:
1. User's EXACT Name: "${userName}". You MUST ONLY address the user by this exact name or "يا هندسة".
2. Reply STRICTLY in 100% Egyptian Arabic (العامية المصرية).
3. PROHIBITION: NEVER use Chinese or Japanese characters.

💰 PRICING & CALCULATION RULES (STRICTLY ADHERE TO THESE):
- سعر الكيلو من (البرسيم الحجازي + بروبايوتيك) ثابت = 12.5 جنيه لجميع الحيوانات.
- الدواجن البياضة: استهلاك 100 جرام/يوم للفرخة. (80% علف أساسي بسعر 25 جنيه/كجم، و 20% برسيم).
- البط البياض: استهلاك 250 جرام/يوم للبطة. (60% علف أساسي بسعر 20 جنيه/كجم، و 40% برسيم).
- الأغنام الولادة: استهلاك 1 كيلو/يوم للنعجة. (90% علف أساسي بسعر 18 جنيه/كجم، و 10% برسيم).
- الأسماك: استهلاك 6 جرام/يوم للسمكة. (60% علف أساسي بسعر 30 جنيه/كجم، و 40% برسيم).
(استخدم هذه الأرقام الدقيقة دائماً لحساب التكلفة والتوفير إذا طلب منك المستخدم).

📊 REAL-TIME USER DATA:
- User Name: ${userName} - Flocks: ${flocksText} - Feed Calculations: ${calcText} - Orders: ${ordersText}`;

        let messagesForGroq = [ { role: "system", content: systemInstruction } ];
        try {
            const { data: history } = await supabase.from('chat_messages').select('sender, content').eq('user_id', userId).order('created_at', { ascending: false }).limit(6);
            if (history && history.length > 0) {
                history.reverse().forEach(msg => {
                    if (msg.content && typeof msg.content === 'string') {
                        messagesForGroq.push({ role: msg.sender === 'ai' ? 'assistant' : 'user', content: msg.content });
                    }
                });
            }
        } catch (e) { console.log("Chat history skip"); }

        let modelToUse = "llama-3.3-70b-versatile"; 
        let currentUserContent = userText;  
        
        if (imageBase64) {
            modelToUse = "llama-3.2-11b-vision-preview"; 
            currentUserContent = [
                { type: "text", text: userText },
                { type: "image_url", image_url: { url: `data:image/jpeg;base64,${imageBase64}` } }
            ];
        }
        messagesForGroq.push({ role: "user", content: currentUserContent });

        const groqApiKey = process.env.GROQ_API_KEY; 
        const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${groqApiKey}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                model: modelToUse, 
                messages: messagesForGroq, 
                temperature: 0.3, 
                top_p: 0.9,
                max_tokens: 1024
            })
        });

        const data = await response.json();
        if (!response.ok || data.error) throw new Error(`Groq Error: ${data.error ? data.error.message : response.status}`);

        const aiReply = data.choices[0].message.content;

        try {
            await supabase.from('chat_messages').insert([
                { user_id: userId, sender: 'user', content: imageBase64 ? `[📸 صورة مرفقة] ${userText}` : userText },
                { user_id: userId, sender: 'ai', content: aiReply }
            ]);
        } catch (e) {}
        
        return res.status(200).json({ reply: aiReply });

    } catch (err) {
        console.error("🔥 Groq AI Error:", err.message || err);
        return res.status(500).json({ reply: `حدث خطأ: ${err.message}` });
    }
});

app.listen(port, () => {
    console.log(`🚀 السيرفر شغال بنجاح على بورت: ${port}`);
});

module.exports = app;