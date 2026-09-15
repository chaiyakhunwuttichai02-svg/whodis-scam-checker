const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false } // จำเป็นสำหรับการเชื่อมต่อ Supabase
});

// ทดสอบการเชื่อมต่อ
pool.connect((err) => {
    if (err) {
        console.error('เกิดข้อผิดพลาดในการเชื่อมต่อฐานข้อมูล:', err.stack);
    } else {
        console.log('เชื่อมต่อฐานข้อมูล Supabase สำเร็จแล้ว!');
    }
});

module.exports = pool;