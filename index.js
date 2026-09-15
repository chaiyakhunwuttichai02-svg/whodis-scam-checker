const express = require('express');
const session = require('express-session');
const path = require('path');
const bcrypt = require('bcrypt');
const multer = require('multer');
const fs = require('fs');
const db = require('./db'); 

// 1. สร้าง app (ต้องอยู่ก่อนการเรียกใช้ app เสมอ)
const app = express();

// 2. สร้างโฟลเดอร์ public/uploads อัตโนมัติถ้ายังไม่มี
const uploadDir = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

// 3. ตั้งค่าระบบอัปโหลดไฟล์
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadDir),
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname);
        cb(null, 'slip_' + Date.now() + ext);
    }
});
const upload = multer({ 
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 }, // จำกัด 5MB
    fileFilter: (req, file, cb) => {
        if (['image/jpeg', 'image/png', 'image/webp'].includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('อนุญาตเฉพาะไฟล์รูปภาพ JPG, PNG, WEBP เท่านั้น'));
        }
    }
});

// 4. ตั้งค่าให้ระบบใช้ EJS และ โฟลเดอร์ public
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public')); // <--- ย้ายมาอยู่ตรงนี้

// 5. ตั้งค่าระบบ Login (Session)
app.use(session({
    secret: 'whodis_super_secret',
    resave: false,
    saveUninitialized: false
}));


// ==========================================
// 6. เส้นทางหน้าเว็บ (Routes) ทั้งหมด
// ==========================================

// หน้าแรก (Index) + ระบบค้นหา
app.get('/', async (req, res) => {
    const searchTerm = req.query.search || '';
    let searchResults = [];
    let searchError = '';
    let hasSearched = false;

    if (searchTerm !== '') {
        hasSearched = true;
        if (searchTerm.length < 4) {
            searchError = 'กรุณากรอกอย่างน้อย 4 ตัวอักษรหรือ 4 ตัวเลข';
        } else {
            try {
                // บันทึกประวัติ
                await db.query('INSERT INTO search_logs (search_term) VALUES ($1)', [searchTerm]);
                
                // ค้นหา
                const result = await db.query(
                    "SELECT * FROM reports WHERE status = 'approved' AND (scammer_name LIKE $1 OR bank_account LIKE $1) ORDER BY created_at DESC",
                    [`%${searchTerm}%`]
                );
                searchResults = result.rows;
            } catch (error) {
                searchError = 'เกิดข้อผิดพลาดในการค้นหาข้อมูล';
            }
        }
    }

    res.render('index', { 
        current_page: 'index.php',
        user: req.session.user_id ? { username: req.session.username } : null,
        searchTerm, searchResults, searchError, hasSearched
    });
});

// หน้า Scam Checker
app.get('/checker', (req, res) => {
    res.render('checker', { 
        current_page: 'checker.php',
        user: req.session.user_id ? { username: req.session.username } : null
    });
});

// หน้า Login
app.get('/login', (req, res) => {
    if (req.session.user_id) return res.redirect('/');
    res.render('login', { error_message: '' });
});

app.post('/login', async (req, res) => {
    const email = req.body.email || '';
    const password = req.body.password || '';

    if (email && password) {
        try {
            const result = await db.query("SELECT * FROM users WHERE LOWER(email) = LOWER($1)", [email]);
            const user = result.rows[0];
            let isPasswordValid = false;

            if (user) {
                if (password === user.password) {
                    isPasswordValid = true;
                } else {
                    isPasswordValid = await bcrypt.compare(password, user.password);
                }
            }

            if (isPasswordValid) {
                req.session.user_id = user.id;
                req.session.username = user.username;
                req.session.role = (user.role || 'user').toLowerCase().trim();
                
                if (req.session.role === 'admin') res.redirect('/admin_reports');
                else res.redirect('/');
            } else {
                res.render('login', { error_message: 'อีเมลหรือรหัสผ่านไม่ถูกต้อง!' });
            }
        } catch (error) {
            res.render('login', { error_message: 'เกิดข้อผิดพลาดในการเชื่อมต่อระบบ' });
        }
    } else {
        res.render('login', { error_message: 'กรุณากรอกข้อมูลให้ครบถ้วน!' });
    }
});

// หน้า Logout
app.get('/logout', (req, res) => {
    req.session.destroy(() => res.redirect('/login'));
});

// หน้า Register
app.get('/register', (req, res) => {
    if (req.session.user_id) return res.redirect('/');
    res.render('register', { error: '', success: '', current_page: 'register.php' });
});

app.post('/register', async (req, res) => {
    const username = (req.body.username || '').trim();
    const email = (req.body.email || '').trim();
    const password = req.body.password || '';
    const confirmPassword = req.body.confirm_password || '';

    if (!username || !email || !password || !confirmPassword) return res.render('register', { error: 'กรุณากรอกข้อมูลให้ครบทุกช่อง', success: '' });
    if (password !== confirmPassword) return res.render('register', { error: 'รหัสผ่านและการยืนยันรหัสผ่านไม่ตรงกัน', success: '' });
    if (password.length < 6) return res.render('register', { error: 'รหัสผ่านต้องมีอย่างน้อย 6 ตัวอักษรขึ้นไป', success: '' });

    try {
        const checkQuery = await db.query('SELECT COUNT(*) FROM users WHERE username = $1 OR email = $2', [username, email]);
        if (parseInt(checkQuery.rows[0].count) > 0) return res.render('register', { error: 'ชื่อผู้ใช้หรืออีเมลนี้ถูกใช้งานไปแล้ว', success: '' });

        const hashedPassword = await bcrypt.hash(password, 10);
        await db.query('INSERT INTO users (username, email, password) VALUES ($1, $2, $3)', [username, email, hashedPassword]);
        res.render('register', { error: '', success: 'สมัครสมาชิกสำเร็จ! กรุณากลับไปที่หน้าเข้าสู่ระบบ' });
    } catch (error) {
        res.render('register', { error: 'เกิดข้อผิดพลาดในการเชื่อมต่อฐานข้อมูล', success: '' });
    }
});

// หน้า Knowledge
app.get('/knowledge', (req, res) => {
    if (!req.session.user_id) return res.redirect('/login');
    res.render('knowledge', { current_page: 'knowledge.php', user: { username: req.session.username } });
});

// หน้า Emergency
app.get('/emergency', (req, res) => {
    if (!req.session.user_id) return res.redirect('/login');
    res.render('emergency', { current_page: 'emergency.php', user: { username: req.session.username } });
});

// หน้า Forgot Password
app.get('/forgot_password', (req, res) => {
    res.render('forgot_password', { error: '', success: '', current_page: 'forgot_password.php' });
});

app.post('/forgot_password', async (req, res) => {
    const email = (req.body.email || '').trim();
    if (!email) return res.render('forgot_password', { error: 'กรุณากรอกอีเมลของคุณ', success: '' });

    try {
        const result = await db.query('SELECT id FROM users WHERE email = $1', [email]);
        if (result.rows[0]) res.render('forgot_password', { error: '', success: 'ระบบได้ส่งลิงก์สำหรับรีเซ็ตรหัสผ่านไปที่อีเมลของคุณแล้ว (จำลองการส่งสำเร็จ)' });
        else res.render('forgot_password', { error: '', success: 'หากอีเมลนี้มีอยู่ในระบบ คุณจะได้รับลิงก์รีเซ็ตรหัสผ่านเร็วๆ นี้' });
    } catch (error) {
        res.render('forgot_password', { error: 'เกิดข้อผิดพลาดในการเชื่อมต่อฐานข้อมูล', success: '' });
    }
});

// หน้า Report
app.get('/report', (req, res) => {
    if (!req.session.user_id) return res.redirect('/login');
    res.render('report', { current_page: 'report.php', user: { username: req.session.username }, successMessage: '', errorMessage: '' });
});

app.post('/report', upload.single('evidence_file'), async (req, res) => {
    if (!req.session.user_id) return res.redirect('/login');

    const { scam_type, scammer_name, bank_account, bank_name, contact_channel, incident_date, claim_amount, incident_details } = req.body;
    let evidenceFile = req.file ? req.file.filename : null;

    try {
        const fullDetails = `[${scam_type}] ${incident_details}`;
        await db.query(
            'INSERT INTO reports (user_id, scammer_name, bank_account, bank_name, incident_date, claim_amount, incident_details, evidence_file, status) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)',
            [req.session.user_id, scammer_name, bank_account, bank_name, incident_date, claim_amount, fullDetails, evidenceFile, 'UNDER INVESTIGATION']
        );
        res.render('report', { current_page: 'report.php', user: { username: req.session.username }, successMessage: 'บันทึกรายงานเบาะแสของคุณเรียบร้อยแล้ว ข้อมูลจะถูกนำไปตรวจสอบต่อไป', errorMessage: '' });
    } catch (error) {
        console.error(error);
        res.render('report', { current_page: 'report.php', user: { username: req.session.username }, successMessage: '', errorMessage: 'เกิดข้อผิดพลาดในระบบฐานข้อมูล' });
    }
});

// หน้า Stats
app.get('/stats', (req, res) => {
    if (!req.session.user_id) return res.redirect('/login');
    res.render('stats', { current_page: 'stats.php', user: { username: req.session.username } });
});
// ==========================================
// เส้นทางสำหรับ Admin (Admin Reports)
// ==========================================
app.get('/admin_reports', async (req, res) => {
    // 1. ตรวจสอบสิทธิ์ว่าเป็น Admin หรือไม่
    if (!req.session.user_id || req.session.role !== 'admin') {
        return res.redirect('/login');
    }

    const current_view = req.query.view || 'reports';
    const current_filter = req.query.filter || 'all';
    let error = null;
    let reports = [];
    let users_list = [];
    let pending_count = 0, approved_count = 0, rejected_count = 0, total_reports = 0;

    try {
        if (current_view === 'reports') {
            // ดึงสถิติ
            const statsResult = await db.query("SELECT status FROM reports");
            total_reports = statsResult.rows.length;
            statsResult.rows.forEach(r => {
                const s = (r.status || 'pending').toLowerCase();
                if (s === 'approved') approved_count++;
                else if (s === 'rejected') rejected_count++;
                else pending_count++;
            });

            // ดึงข้อมูลตารางตาม Filter
            let sql = "SELECT * FROM reports ";
            if (current_filter === 'pending') sql += "WHERE status = 'pending' OR status = 'UNDER INVESTIGATION' OR status IS NULL ";
            else if (current_filter === 'approved') sql += "WHERE status = 'approved' ";
            else if (current_filter === 'rejected') sql += "WHERE status = 'rejected' ";
            sql += "ORDER BY created_at DESC";
            
            const reportsResult = await db.query(sql);
            reports = reportsResult.rows;
        } else if (current_view === 'users') {
            const usersResult = await db.query("SELECT * FROM users ORDER BY id DESC");
            users_list = usersResult.rows;
        }
    } catch (err) {
        console.error(err);
        error = "เกิดข้อผิดพลาดในการดึงข้อมูลจากฐานข้อมูล";
    }

    res.render('admin_reports', {
        admin_name: req.session.username || 'Admin',
        admin_email: 'admin@whodis.com', 
        current_view,
        current_filter,
        error,
        reports,
        users_list,
        pending_count,
        approved_count,
        rejected_count,
        total_reports
    });
});

app.post('/admin_reports', async (req, res) => {
    // ตรวจสอบสิทธิ์
    if (!req.session.user_id || req.session.role !== 'admin') {
        return res.redirect('/login');
    }

    const report_id = req.body.report_id;
    const action = req.body.action;
    const current_filter = req.query.filter || 'all';

    try {
        if (action === 'approve') {
            await db.query("UPDATE reports SET status = 'approved' WHERE id = $1", [report_id]);
        } else if (action === 'reject') {
            await db.query("UPDATE reports SET status = 'rejected' WHERE id = $1", [report_id]);
        } else if (action === 'delete') {
            await db.query("DELETE FROM reports WHERE id = $1", [report_id]);
        }
    } catch (err) {
        console.error(err);
    }

    // ทำรายการเสร็จให้ Redirect กลับไปหน้าเดิม
    res.redirect(`/admin_reports?view=reports&filter=${current_filter}`);
});
// ==========================================
// 7. เปิดเซิร์ฟเวอร์
// ==========================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 เซิร์ฟเวอร์รันแล้ว! เปิดเบราว์เซอร์ไปที่ http://localhost:${PORT}`);
});