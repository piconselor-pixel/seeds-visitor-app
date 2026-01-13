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

// SQL Server Connection Config
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

// Email Config – your SMTP
const EMAIL_CONFIG = {
  host: 'smtp.gmail.com',
  port: 587,
  secure: false,
  auth: {
    user: 'punit.tiwari@seedsfincap.com',
    pass: 'bnvvcegikhpzphvk'
  }
};

const JWT_SECRET = 'SeedsVisitorSystem2025_SuperSecureKey!';

const transporter = nodemailer.createTransport(EMAIL_CONFIG);

let sqlPool;

// Init DB + tables
async function initSqlConnection() {
  sqlPool = await sql.connect(SQL_CONFIG);
  console.log('✅ SQL Server Connected - VisitorDB');

  await transporter.verify().catch(err =>
    console.log('⚠️ Email verify failed:', err.message)
  );

  await createTables();
}

// bcrypt hash for "admin123"
const ADMIN_HASH = '$2b$10$CwTycUXWue0Thq9StjUM0uJ8aBKJuPqU7QXtNCFywgKx4B3bWXO5e'; // admin123[web:52]

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
    // Default admin user: admin@seedsfincap.com / admin123
    `IF EXISTS (SELECT 1 FROM vs_users WHERE username = 'admin')
     BEGIN
       UPDATE vs_users
       SET email = 'admin@seedsfincap.com',
           password = '${ADMIN_HASH}',
           role = 'admin'
       WHERE username = 'admin';
     END
     ELSE
     BEGIN
       INSERT INTO vs_users (username, email, password, role)
       VALUES (
         'admin',
         'admin@seedsfincap.com',
         '${ADMIN_HASH}',
         'admin'
       )
     END`
  ];

  for (const q of queries) {
    try {
      await sqlPool.request().query(q);
    } catch (e) {
      console.log('Table setup warning:', e.message);
    }
  }
  console.log('✅ Tables ready: vs_users, vs_visitors');
}

// Auth middleware (for admin/list APIs)
function authenticateToken(req, res, next) {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: 'Access denied - No token' });

    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ error: 'Invalid token' });
  }
}

// LOGIN
app.post('/api/login', async (req, res) => {
    try {
      const { username, password } = req.body;
      console.log('LOGIN REQUEST:', { username, passwordLength: password ? password.length : 0 });
  
      const r = sqlPool.request();
      r.input('username', sql.NVarChar, username);
      const result = await r.query(
        'SELECT * FROM vs_users WHERE username = @username OR email = @username'
      );
  
      console.log('DB USERS FOUND:', result.recordset.length);
      if (!result.recordset.length) {
        console.log('LOGIN FAILED: user not found for', username);
        return res.status(401).json({ error: 'Invalid credentials' });
      }
  
      const user = result.recordset[0];
      console.log('DB USER ROW:', {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        hashPrefix: (user.password || '').substring(0, 20)
      });
  
      const ok = await bcrypt.compare(password, user.password);
      console.log('BCRYPT RESULT:', ok);
  
      if (!ok) {
        console.log('LOGIN FAILED: password mismatch for', username);
        return res.status(401).json({ error: 'Invalid credentials' });
      }
  
      const token = jwt.sign(
        { id: user.id, username: user.username, role: user.role },
        JWT_SECRET,
        { expiresIn: '24h' }
      );
  
      console.log('LOGIN SUCCESS:', { id: user.id, username: user.username, role: user.role });
  
      res.json({
        token,
        user: { id: user.id, username: user.username, role: user.role }
      });
    } catch (err) {
      console.error('LOGIN ERROR:', err);
      res.status(500).json({ error: err.message });
    }
  });
  
// PUBLIC – Create Visitor + Email + QR (no token)
app.post('/api/visitors', async (req, res) => {
  try {
    const { visitor_name, mobile, host_employee, host_email, purpose, photo_base64 } = req.body;

    if (!visitor_name || !host_email || !purpose) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

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

    const r = sqlPool.request();
    r.input('visitor_name', sql.NVarChar, visitor_name);
    r.input('mobile', sql.NVarChar, mobile || null);
    r.input('host_employee', sql.NVarChar, host_employee || null);
    r.input('host_email', sql.NVarChar, host_email);
    r.input('purpose', sql.NVarChar, purpose);
    r.input('photo_base64', sql.NVarChar, photo_base64 || null);
    r.input('qr_code_data', sql.NVarChar, JSON.stringify(qrData));
    r.input('created_by', sql.NVarChar, 'reception');

    const insertResult = await r.query(`
      INSERT INTO vs_visitors
        (visitor_name, mobile, host_employee, host_email, purpose, photo_base64, qr_code_data, created_by)
      OUTPUT INSERTED.id
      VALUES
        (@visitor_name, @mobile, @host_employee, @host_email, @purpose, @photo_base64, @qr_code_data, @created_by)
    `);

    const visitorId = insertResult.recordset[0].id;

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
            ${photo_base64 ? `<img src="cid:visitor-photo" style="max-width: 300px; border: 2px solid #007bff; border-radius: 8px;" />` : '<p>No photo available</p>'}
          </div>
          <div style="margin: 20px 0;">
            <h3>📱 WhatsApp QR Pass:</h3>
            <img src="${qrCodeDataURL}" style="max-width: 200px; border: 2px solid #25D366; border-radius: 8px;" />
          </div>
        </div>
      `,
      attachments: photo_base64
        ? [{
            filename: 'visitor-photo.jpg',
            content: Buffer.from(photo_base64, 'base64'),
            cid: 'visitor-photo'
          }]
        : []
    };

    transporter.sendMail(mailOptions).catch(err =>
      console.log('Email send error:', err.message)
    );

    res.json({
      success: true,
      id: visitorId,
      qrCode: qrCodeDataURL,
      message: 'Visitor checked-in successfully!'
    });
  } catch (err) {
    console.error('Visitor error:', err);
    res.status(500).json({ error: err.message });
  }
});

// PROTECTED – Check-out
app.put('/api/visitors/:id/checkout', authenticateToken, async (req, res) => {
  try {
    const r = sqlPool.request();
    r.input('id', sql.Int, req.params.id);
    const result = await r.query(`
      UPDATE vs_visitors
      SET checkout_time = GETDATE(), status = 'checked_out'
      WHERE id = @id
    `);
    if (result.rowsAffected[0] > 0) {
      res.json({ success: true });
    } else {
      res.status(404).json({ error: 'Visitor not found' });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PROTECTED – Admin stats
app.get('/api/admin/stats', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  try {
    const r = sqlPool.request();
    const todayStats = await r.query(`
      SELECT 
        COUNT(*) AS total_today,
        SUM(CASE WHEN status = 'checked_in' THEN 1 ELSE 0 END) AS active,
        SUM(CASE WHEN status = 'checked_out' THEN 1 ELSE 0 END) AS checked_out
      FROM vs_visitors
      WHERE CAST(checkin_time AS DATE) = CAST(GETDATE() AS DATE)
    `);
    const allTime = await r.query('SELECT COUNT(*) AS total_all FROM vs_visitors');
    res.json({ today: todayStats.recordset[0], allTime: allTime.recordset[0].total_all });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PROTECTED – List visitors
app.get('/api/visitors', authenticateToken, async (req, res) => {
  try {
    const { date, status } = req.query;
    let query = `
      SELECT id, visitor_name, mobile, host_employee, host_email, purpose,
             checkin_time, checkout_time, status, created_by
      FROM vs_visitors
      WHERE 1=1
    `;
    const r = sqlPool.request();

    if (date) {
      query += ` AND CAST(checkin_time AS DATE) = @date`;
      r.input('date', sql.Date, date);
    }
    if (status) {
      query += ` AND status = @status`;
      r.input('status', sql.NVarChar, status);
    }

    query += ' ORDER BY checkin_time DESC OFFSET 0 ROWS FETCH NEXT 100 ROWS ONLY';

    const result = await r.query(query);
    res.json(result.recordset);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PROTECTED – Export CSV last 7 days
app.get('/api/admin/export', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin only' });
  }
  try {
    const r = sqlPool.request();
    const result = await r.query(`
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
    res.send('\ufeff' + csv);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Start server
const PORT = process.env.PORT || 3032;
initSqlConnection()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`🚀 Visitor System running on http://localhost:${PORT}`);
      console.log(`📊 Admin Dashboard: http://localhost:${PORT}/admin.html`);
      console.log(`👤 Admin login: admin@seedsfincap.com / admin123`);
    });
  })
  .catch(err => console.error('Startup error:', err));