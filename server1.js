const express = require('express');
const sql = require('mssql');
const nodemailer = require('nodemailer');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const QRCode = require('qrcode');
const bodyParser = require('body-parser');
const path = require('path');

const app = express();

// Middleware
app.use(cors());
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ limit: '50mb', extended: true }));
app.use(express.static('public'));

// SQL Server Connection Config (YOUR EXACT DETAILS)
const SQL_CONFIG = {
    user: 'sa',
    password: 'Seeds_da@123',
    server: '122.160.72.187',
    port: 4022,
    database: 'VisitorDB',
    options: {
        encrypt: false,
        trustServerCertificate: true,
        enableArithAbort: true
    },
    pool: {
        max: 10,
        min: 0,
        idleTimeoutMillis: 30000
    }
};

// ✅ FIXED: Email Config - UPDATE THESE
const EMAIL_CONFIG = {
    host: 'smtp.gmail.com',
    port: 587,
    secure: false, // true for 465, false for other ports
    auth: {
        user: 'punit.tiwari@seedsfincap.com',        // ← UPDATE YOUR EMAIL
        pass: 'bnvvcegikhpzphvk'    // ← UPDATE APP PASSWORD
    }
};

const JWT_SECRET = 'SeedsVisitorSystem2025_SuperSecureKey!';

// ✅ FIXED: createTransport (not createTransporter)
const transporter = nodemailer.createTransport(EMAIL_CONFIG);

// Global SQL connection pool
let sqlPool;

// Initialize SQL connection
async function initSqlConnection() {
    try {
        sqlPool = await sql.connect(SQL_CONFIG);
        console.log('✅ SQL Server Connected - VisitorDB');
        
        // Test email connection
        await transporter.verify();
        console.log('✅ Email SMTP Connected');
        
        // Create tables if not exist
        await createTables();
    } catch (err) {
        console.error('❌ SQL Connection Failed:', err);
    }
}

// Create required tables (vs_users, vs_visitors)
async function createTables() {
    const queries = [
        `IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='vs_users' AND xtype='U')
        BEGIN
            CREATE TABLE vs_users (
                id INT IDENTITY(1,1) PRIMARY KEY,
                username NVARCHAR(50) UNIQUE NOT NULL,
                email NVARCHAR(100) UNIQUE NOT NULL,
                password NVARCHAR(255) NOT NULL,
                role NVARCHAR(20) DEFAULT 'reception',
                created_at DATETIME2 DEFAULT GETDATE()
            )
        END`,
        
        `IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='vs_visitors' AND xtype='U')
        BEGIN
            CREATE TABLE vs_visitors (
                id INT IDENTITY(1,1) PRIMARY KEY,
                visitor_name NVARCHAR(100) NOT NULL,
                mobile NVARCHAR(15),
                host_employee NVARCHAR(100),
                host_email NVARCHAR(100) NOT NULL,
                purpose NVARCHAR(MAX),
                photo_base64 NVARCHAR(MAX),
                qr_code_data NVARCHAR(MAX),
                checkin_time DATETIME2 DEFAULT GETDATE(),
                checkout_time DATETIME2 NULL,
                status NVARCHAR(20) DEFAULT 'checked_in',
                created_by NVARCHAR(50),
                created_at DATETIME2 DEFAULT GETDATE()
            )
        END`,
        
        // Default admin user (password: 'admin123')
        `IF NOT EXISTS (SELECT 1 FROM vs_users WHERE username = 'admin')
        BEGIN
            INSERT INTO vs_users (username, email, password, role) 
            VALUES ('admin', 'admin@seedsfincap.com', 
            '$2b$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'admin')
        END`
    ];
    
    for (const query of queries) {
        try {
            await sqlPool.request().query(query);
        } catch (err) {
            console.log('Table setup warning:', err.message);
        }
    }
    console.log('✅ Tables ready: vs_users, vs_visitors');
}

// Auth middleware
const authenticateToken = async (req, res, next) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];
        
        if (!token) {
            return res.status(401).json({ error: 'Access denied - No token' });
        }
        
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        res.status(403).json({ error: 'Invalid token' });
    }
};

// ===== API ROUTES =====

// 1. Login
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const request = sqlPool.request();
        request.input('username', sql.NVarChar, username);
        
        const result = await request.query('SELECT * FROM vs_users WHERE username = @username OR email = @username');
        
        if (result.recordset.length > 0) {
            const user = result.recordset[0];
            if (await bcrypt.compare(password, user.password)) {
                const token = jwt.sign(
                    { id: user.id, username: user.username, role: user.role }, 
                    JWT_SECRET, 
                    { expiresIn: '24h' }
                );
                res.json({
                    token,
                    user: {
                        id: user.id,
                        username: user.username,
                        role: user.role
                    }
                });
            } else {
                res.status(401).json({ error: 'Invalid credentials' });
            }
        } else {
            res.status(401).json({ error: 'Invalid credentials' });
        }
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 2. Create Visitor + Email + QR Code
app.post('/api/visitors', authenticateToken, async (req, res) => {
    try {
        const { visitor_name, mobile, host_employee, host_email, purpose, photo_base64 } = req.body;
        const user = req.user;
        
        // Generate QR data
        const qrData = {
            id: `VIS-${Date.now()}`,
            name: visitor_name,
            mobile: mobile || '',
            host: host_employee || '',
            purpose: purpose || '',
            checkin: new Date().toISOString(),
            status: 'checked_in'
        };
        const qrCodeDataURL = await QRCode.toDataURL(JSON.stringify(qrData));
        
        // Save to vs_visitors
        const request = sqlPool.request();
        request.input('visitor_name', sql.NVarChar, visitor_name);
        request.input('mobile', sql.NVarChar, mobile);
        request.input('host_employee', sql.NVarChar, host_employee);
        request.input('host_email', sql.NVarChar, host_email);
        request.input('purpose', sql.NText, purpose);
        request.input('photo_base64', sql.NText, photo_base64);
        request.input('qr_code_data', sql.NText, JSON.stringify(qrData));
        request.input('created_by', sql.NVarChar, user.username);
        
        const result = await request.query(`
            INSERT INTO vs_visitors (visitor_name, mobile, host_employee, host_email, purpose, 
                                   photo_base64, qr_code_data, created_by)
            OUTPUT INSERTED.id
            VALUES (@visitor_name, @mobile, @host_employee, @host_email, @purpose, 
                   @photo_base64, @qr_code_data, @created_by)
        `);
        
        const visitorId = result.recordset[0].id;
        
        // Send Email to host
        const mailOptions = {
            from: `"Seeds FinCap" <${EMAIL_CONFIG.auth.user}>`,
            to: host_email,
            subject: `🛡️ New Visitor Check-in: ${visitor_name}`,
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px;">
                    <h2 style="color: #007bff;">🔐 New Visitor Alert - Seeds FinCap</h2>
                    <table style="width: 100%; border-collapse: collapse;">
                        <tr><td style="padding: 8px;"><strong>👤 Name:</strong></td><td>${visitor_name}</td></tr>
                        <tr><td style="padding: 8px;"><strong>📱 Mobile:</strong></td><td>${mobile || 'N/A'}</td></tr>
                        <tr><td style="padding: 8px;"><strong>👥 Host:</strong></td><td>${host_employee || 'N/A'}</td></tr>
                        <tr><td style="padding: 8px;"><strong>📝 Purpose:</strong></td><td>${purpose}</td></tr>
                        <tr><td style="padding: 8px;"><strong>⏰ Check-in:</strong></td><td>${new Date().toLocaleString()}</td></tr>
                    </table>
                    <div style="margin: 20px 0;">
                        <h3>📸 Visitor Photo:</h3>
                        <img src="cid:visitor-photo" style="max-width: 300px; border: 2px solid #007bff; border-radius: 8px;" />
                    </div>
                    <div style="margin: 20px 0;">
                        <h3>📱 WhatsApp QR Pass:</h3>
                        <img src="${qrCodeDataURL}" style="max-width: 200px; border: 2px solid #25D366; border-radius: 8px;" />
                        <p style="color: #666; font-size: 14px;">Share this QR with visitor for security check-out</p>
                    </div>
                </div>
            `,
            attachments: [{
                filename: 'visitor-photo.jpg',
                content: Buffer.from(photo_base64, 'base64'),
                cid: 'visitor-photo'
            }]
        };
        
        await transporter.sendMail(mailOptions);
        
        res.json({ 
            success: true, 
            id: visitorId, 
            qrCode: qrCodeDataURL,
            message: 'Visitor checked-in & email sent successfully!'
        });
        
    } catch (err) {
        console.error('Visitor creation error:', err);
        res.status(500).json({ error: err.message });
    }
});

// 3. Check-out visitor
app.put('/api/visitors/:id/checkout', authenticateToken, async (req, res) => {
    try {
        const request = sqlPool.request();
        request.input('id', sql.Int, req.params.id);
        
        const result = await request.query(`
            UPDATE vs_visitors 
            SET checkout_time = GETDATE(), status = 'checked_out' 
            WHERE id = @id
        `);
        
        if (result.rowsAffected[0] > 0) {
            res.json({ success: true, message: 'Visitor checked-out successfully' });
        } else {
            res.status(404).json({ error: 'Visitor not found' });
        }
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 4. Admin Stats Dashboard
app.get('/api/admin/stats', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    
    try {
        const request = sqlPool.request();
        const result = await request.query(`
            SELECT 
                COUNT(*) as total_today,
                SUM(CASE WHEN status = 'checked_in' THEN 1 ELSE 0 END) as active,
                SUM(CASE WHEN status = 'checked_out' THEN 1 ELSE 0 END) as checked_out
            FROM vs_visitors 
            WHERE CAST(checkin_time AS DATE) = CAST(GETDATE() AS DATE)
        `);
        
        const totalResult = await request.query('SELECT COUNT(*) as total_all FROM vs_visitors');
        
        res.json({
            today: result.recordset[0],
            allTime: totalResult.recordset[0].total_all
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 5. Get Visitors List (with filters)
app.get('/api/visitors', authenticateToken, async (req, res) => {
    try {
        const { date, status } = req.query;
        let query = `
            SELECT id, visitor_name, mobile, host_employee, host_email, purpose, 
                   checkin_time, checkout_time, status, created_by
            FROM vs_visitors 
            WHERE 1=1
        `;
        const request = sqlPool.request();
        let params = {};
        
        if (date) {
            query += ` AND CAST(checkin_time AS DATE) = @date`;
            params.date = date;
            request.input('date', sql.Date, date);
        }
        if (status) {
            query += ` AND status = @status`;
            params.status = status;
            request.input('status', sql.NVarChar, status);
        }
        if (req.user.role === 'reception') {
            query += ` AND created_by = @username`;
            request.input('username', sql.NVarChar, req.user.username);
        }
        
        query += ` ORDER BY checkin_time DESC OFFSET 0 ROWS FETCH NEXT 100 ROWS ONLY`;
        
        const result = await request.query(query);
        res.json(result.recordset);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 6. Export CSV (Admin Only - Last 7 days)
app.get('/api/admin/export', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin only' });
    }
    
    try {
        const request = sqlPool.request();
        const result = await request.query(`
            SELECT 
                id, visitor_name, mobile, host_employee, host_email, 
                purpose, checkin_time, checkout_time, status, created_by
            FROM vs_visitors 
            WHERE checkin_time >= DATEADD(day, -7, GETDATE())
            ORDER BY checkin_time DESC
        `);
        
        const visitors = result.recordset;
        const csv = [
            ['ID', 'Name', 'Mobile', 'Host', 'Email', 'Purpose', 'Check-in', 'Check-out', 'Status', 'Created By'],
            ...visitors.map(v => [
                v.id,
                `"${v.visitor_name}"`,
                v.mobile || '',
                `"${v.host_employee || ''}"`,
                v.host_email,
                `"${(v.purpose || '').replace(/"/g, '""')}"`,
                v.checkin_time,
                v.checkout_time || '',
                v.status,
                v.created_by
            ])
        ].map(row => row.join(',')).join('\n');
        
        res.header('Content-Type', 'text/csv');
        res.header('Content-Disposition', `attachment; filename="Seeds-Security-Audit-${new Date().toISOString().split('T')[0]}.csv"`);
        res.send('\ufeff' + csv); // BOM for Excel
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Health check
app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Start Server
const PORT = process.env.PORT || 3032;

async function startServer() {
    await initSqlConnection();
    app.listen(PORT, () => {
        console.log(`🚀 Seeds Visitor System running on http://localhost:${PORT}`);
        console.log(`📊 Admin Dashboard: http://localhost:${PORT}/admin.html`);
        console.log(`👤 Login: admin@seedsfincap.com / admin123`);
        console.log(`📧 Update EMAIL_CONFIG in server.js with your Gmail!`);
    });
}

startServer().catch(console.error);