const express = require('express');
const sql = require('mssql');
const nodemailer = require('nodemailer');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const QRCode = require('qrcode');
const bodyParser = require('body-parser');
const path = require('path');
require('dotenv').config(); // Add this for environment variables

const app = express();

// Middleware
app.use(cors());
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ limit: '50mb', extended: true }));
app.use(express.static('public'));

// Environment variable validation
const requiredEnvVars = [
  'DB_USER', 'DB_PASSWORD', 'DB_SERVER', 'DB_NAME',DB_PORT,
  'JWT_SECRET', 'EMAIL_USER', 'EMAIL_PASS'
];

const missingVars = requiredEnvVars.filter(varName => !process.env[varName]);
if (missingVars.length > 0 && process.env.NODE_ENV !== 'test') {
  console.error('❌ Missing required environment variables:', missingVars);
  process.exit(1);
}

// SQL Server Connection Config - Using environment variables
const SQL_CONFIG = {
  user: process.env.DB_USER || 'sa',
  password: process.env.DB_PASSWORD || '',
  server: process.env.DB_SERVER || '122.160.72.187',
  port: parseInt(process.env.DB_PORT) || 4022,
  database: process.env.DB_NAME || 'VisitorDB',
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

// Email Config – using environment variables
const EMAIL_CONFIG = {
  host: process.env.EMAIL_HOST || 'smtp.gmail.com',
  port: process.env.EMAIL_PORT || 587,
  secure: false,
  auth: {
    user: process.env.EMAIL_USER || '',
    pass: process.env.EMAIL_PASS || ''
  }
};

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

const transporter = nodemailer.createTransport(EMAIL_CONFIG);

let sqlPool;

// Database connection retry logic
async function connectWithRetry(maxRetries = 5, delay = 5000) {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      sqlPool = await sql.connect(SQL_CONFIG);
      console.log('✅ SQL Server Connected - VisitorDB');
      return true;
    } catch (err) {
      console.error(`❌ Connection attempt ${attempt} failed:`, err.message);
      if (attempt === maxRetries) throw err;
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
}

// Init DB + tables
async function initSqlConnection() {
  try {
    await connectWithRetry();
    
    // Verify email connection
    await transporter.verify().catch(err =>
      console.log('⚠️ Email verify failed:', err.message)
    );

    await createTables();
  } catch (err) {
    console.error('❌ Database initialization failed:', err.message);
    throw err;
  }
}

// Generate password hash for default admin
async function getAdminHash() {
  const defaultPassword = process.env.ADMIN_DEFAULT_PASSWORD || 'admin123';
  return await bcrypt.hash(defaultPassword, 10);
}

async function createTables() {
  try {
    // Create users table
    const createUsersTable = `
      IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='vs_users' AND xtype='U')
      BEGIN
        CREATE TABLE vs_users (
          id INT IDENTITY(1,1) PRIMARY KEY,
          username NVARCHAR(50) UNIQUE NOT NULL,
          email NVARCHAR(100) UNIQUE NOT NULL,
          password NVARCHAR(255) NOT NULL,
          role NVARCHAR(20) DEFAULT 'reception',
          created_at DATETIME2 DEFAULT GETDATE()
        )
      END`;
    
    await sqlPool.request().query(createUsersTable);

    // Create visitors table
    const createVisitorsTable = `
      IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='vs_visitors' AND xtype='U')
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
      END`;
    
    await sqlPool.request().query(createVisitorsTable);

    // Create default admin user
    const adminHash = await getAdminHash();
    const adminEmail = process.env.ADMIN_EMAIL || 'admin@seedsfincap.com';
    
    const adminQuery = `
      IF NOT EXISTS (SELECT 1 FROM vs_users WHERE username = 'admin' OR email = @adminEmail)
      BEGIN
        INSERT INTO vs_users (username, email, password, role)
        VALUES ('admin', @adminEmail, @adminHash, 'admin')
      END
      ELSE
      BEGIN
        UPDATE vs_users 
        SET password = @adminHash, role = 'admin'
        WHERE username = 'admin' OR email = @adminEmail
      END
    `;
    
    const adminRequest = sqlPool.request();
    adminRequest.input('adminEmail', sql.NVarChar, adminEmail);
    adminRequest.input('adminHash', sql.NVarChar, adminHash);
    
    await adminRequest.query(adminQuery);
    
    console.log('✅ Tables ready: vs_users, vs_visitors');
  } catch (err) {
    console.error('❌ Table creation error:', err.message);
    throw err;
  }
}

// Auth middleware
function authenticateToken(req, res, next) {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ 
        error: 'Access denied - No token provided',
        code: 'NO_TOKEN'
      });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        error: 'Token expired',
        code: 'TOKEN_EXPIRED'
      });
    }
    return res.status(403).json({ 
      error: 'Invalid token',
      code: 'INVALID_TOKEN'
    });
  }
}

// Role-based access control middleware
function requireRole(roles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ 
        error: 'Insufficient permissions',
        requiredRoles: roles
      });
    }
    
    next();
  };
}

// LOGIN endpoint
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ 
        error: 'Username and password are required',
        code: 'MISSING_CREDENTIALS'
      });
    }

    const request = sqlPool.request();
    request.input('username', sql.NVarChar, username);
    
    const result = await request.query(`
      SELECT id, username, email, password, role 
      FROM vs_users 
      WHERE username = @username OR email = @username
    `);

    if (!result.recordset.length) {
      // Use bcrypt compare with dummy hash to prevent timing attacks
      await bcrypt.compare(password, '$2b$10$dummyhashforpreventingtimingattacks');
      return res.status(401).json({ 
        error: 'Invalid credentials',
        code: 'INVALID_CREDENTIALS'
      });
    }

    const user = result.recordset[0];
    const passwordValid = await bcrypt.compare(password, user.password);

    if (!passwordValid) {
      return res.status(401).json({ 
        error: 'Invalid credentials',
        code: 'INVALID_CREDENTIALS'
      });
    }

    const token = jwt.sign(
      { 
        id: user.id, 
        username: user.username, 
        email: user.email,
        role: user.role 
      },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      token,
      user: { 
        id: user.id, 
        username: user.username,
        email: user.email,
        role: user.role 
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ 
      error: 'Internal server error',
      code: 'INTERNAL_ERROR'
    });
  }
});

// Create Visitor
app.post('/api/visitors', async (req, res) => {
  try {
    const { 
      visitor_name, 
      mobile, 
      host_employee, 
      host_email, 
      purpose, 
      photo_base64 
    } = req.body;

    // Validation
    if (!visitor_name || !host_email || !purpose) {
      return res.status(400).json({ 
        error: 'Missing required fields: visitor_name, host_email, and purpose are required',
        code: 'MISSING_FIELDS'
      });
    }

    // Email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(host_email)) {
      return res.status(400).json({ 
        error: 'Invalid host email format',
        code: 'INVALID_EMAIL'
      });
    }

    // Generate QR code data
    const qrData = {
      id: `VIS-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      name: visitor_name,
      mobile: mobile || '',
      host: host_employee || '',
      purpose: purpose,
      checkin: new Date().toISOString(),
      status: 'checked_in'
    };

    const qrCodeDataURL = await QRCode.toDataURL(JSON.stringify(qrData));

    // Insert into database
    const request = sqlPool.request();
    request.input('visitor_name', sql.NVarChar, visitor_name);
    request.input('mobile', sql.NVarChar, mobile || null);
    request.input('host_employee', sql.NVarChar, host_employee || null);
    request.input('host_email', sql.NVarChar, host_email);
    request.input('purpose', sql.NVarChar, purpose);
    request.input('photo_base64', sql.NVarChar, photo_base64 || null);
    request.input('qr_code_data', sql.NVarChar, JSON.stringify(qrData));
    request.input('created_by', sql.NVarChar, req.user?.username || 'system');

    const insertResult = await request.query(`
      INSERT INTO vs_visitors
        (visitor_name, mobile, host_employee, host_email, purpose, 
         photo_base64, qr_code_data, created_by)
      OUTPUT INSERTED.id
      VALUES
        (@visitor_name, @mobile, @host_employee, @host_email, @purpose, 
         @photo_base64, @qr_code_data, @created_by)
    `);

    const visitorId = insertResult.recordset[0].id;

    // Send email notification (async, don't wait for it)
    try {
      const mailOptions = {
        from: `"Seeds FinCap Visitor System" <${EMAIL_CONFIG.auth.user}>`,
        to: host_email,
        subject: `🛡️ New Visitor Check-in: ${visitor_name}`,
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px;">
            <h2 style="color: #007bff;">🔐 New Visitor Alert - Seeds FinCap</h2>
            <p>A new visitor has checked in to see you.</p>
            <table style="width: 100%; border-collapse: collapse; border: 1px solid #ddd;">
              <tr style="background-color: #f2f2f2;">
                <th style="padding: 12px; text-align: left;">Field</th>
                <th style="padding: 12px; text-align: left;">Details</th>
              </tr>
              <tr><td style="padding: 8px;"><strong>👤 Visitor Name:</strong></td><td>${visitor_name}</td></tr>
              <tr><td style="padding: 8px;"><strong>📱 Mobile:</strong></td><td>${mobile || 'N/A'}</td></tr>
              <tr><td style="padding: 8px;"><strong>👥 Host Employee:</strong></td><td>${host_employee || 'N/A'}</td></tr>
              <tr><td style="padding: 8px;"><strong>📝 Purpose:</strong></td><td>${purpose}</td></tr>
              <tr><td style="padding: 8px;"><strong>⏰ Check-in Time:</strong></td><td>${new Date().toLocaleString()}</td></tr>
            </table>
            ${photo_base64 ? `
              <div style="margin: 20px 0;">
                <h3>📸 Visitor Photo:</h3>
                <img src="cid:visitor-photo" style="max-width: 300px; border: 2px solid #007bff; border-radius: 8px;" />
              </div>
            ` : ''}
            <div style="margin: 20px 0;">
              <h3>📱 QR Code Pass:</h3>
              <p>Scan this QR code to view visitor details:</p>
              <img src="${qrCodeDataURL}" style="max-width: 200px; border: 2px solid #25D366; border-radius: 8px;" />
            </div>
            <hr style="border: 1px solid #ddd;">
            <p style="color: #666; font-size: 12px;">
              This is an automated notification from Seeds FinCap Visitor Management System.
            </p>
          </div>
        `,
        attachments: photo_base64 ? [{
          filename: `visitor-${visitorId}.jpg`,
          content: Buffer.from(photo_base64, 'base64'),
          cid: 'visitor-photo'
        }] : []
      };

      transporter.sendMail(mailOptions)
        .then(() => console.log(`✅ Email sent to ${host_email}`))
        .catch(err => console.error('❌ Email send error:', err.message));
    } catch (emailErr) {
      console.error('Email generation error:', emailErr.message);
    }

    res.json({
      success: true,
      id: visitorId,
      qrCode: qrCodeDataURL,
      message: 'Visitor checked-in successfully!',
      visitor: {
        name: visitor_name,
        host: host_employee,
        checkinTime: new Date().toISOString()
      }
    });
  } catch (err) {
    console.error('Visitor creation error:', err);
    res.status(500).json({ 
      error: 'Failed to create visitor',
      code: 'VISITOR_CREATION_ERROR',
      details: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  }
});

// Check-out visitor
app.put('/api/visitors/:id/checkout', authenticateToken, async (req, res) => {
  try {
    const visitorId = parseInt(req.params.id);
    
    if (isNaN(visitorId)) {
      return res.status(400).json({ 
        error: 'Invalid visitor ID',
        code: 'INVALID_ID'
      });
    }

    const request = sqlPool.request();
    request.input('id', sql.Int, visitorId);
    request.input('checkoutBy', sql.NVarChar, req.user.username);

    const result = await request.query(`
      UPDATE vs_visitors
      SET checkout_time = GETDATE(), 
          status = 'checked_out'
      WHERE id = @id AND status = 'checked_in'
    `);

    if (result.rowsAffected[0] === 0) {
      return res.status(404).json({ 
        error: 'Visitor not found or already checked out',
        code: 'VISITOR_NOT_FOUND'
      });
    }

    res.json({ 
      success: true,
      message: 'Visitor checked out successfully',
      checkoutTime: new Date().toISOString()
    });
  } catch (err) {
    console.error('Checkout error:', err);
    res.status(500).json({ 
      error: 'Failed to check out visitor',
      code: 'CHECKOUT_ERROR'
    });
  }
});

// Get visitor statistics
app.get('/api/admin/stats', authenticateToken, requireRole(['admin']), async (req, res) => {
  try {
    const request = sqlPool.request();
    
    const todayStats = await request.query(`
      SELECT 
        COUNT(*) AS total_today,
        SUM(CASE WHEN status = 'checked_in' THEN 1 ELSE 0 END) AS active,
        SUM(CASE WHEN status = 'checked_out' THEN 1 ELSE 0 END) AS checked_out,
        COUNT(DISTINCT host_email) AS unique_hosts
      FROM vs_visitors
      WHERE CAST(checkin_time AS DATE) = CAST(GETDATE() AS DATE)
    `);

    const weekStats = await request.query(`
      SELECT 
        COUNT(*) AS total_week,
        CAST(checkin_time AS DATE) AS date,
        COUNT(*) AS daily_count
      FROM vs_visitors
      WHERE checkin_time >= DATEADD(day, -7, GETDATE())
      GROUP BY CAST(checkin_time AS DATE)
      ORDER BY date DESC
    `);

    const allTimeStats = await request.query(`
      SELECT 
        COUNT(*) AS total_all,
        COUNT(DISTINCT host_email) AS total_hosts,
        MIN(checkin_time) AS first_visitor,
        MAX(checkin_time) AS last_visitor
      FROM vs_visitors
    `);

    res.json({
      today: todayStats.recordset[0],
      week: weekStats.recordset,
      allTime: allTimeStats.recordset[0]
    });
  } catch (err) {
    console.error('Stats error:', err);
    res.status(500).json({ 
      error: 'Failed to fetch statistics',
      code: 'STATS_ERROR'
    });
  }
});

// List visitors with filtering and pagination
app.get('/api/visitors', authenticateToken, async (req, res) => {
  try {
    const { 
      date, 
      status, 
      host_email,
      page = 1, 
      limit = 50,
      search 
    } = req.query;

    const pageNum = parseInt(page);
    const limitNum = parseInt(limit);
    const offset = (pageNum - 1) * limitNum;

    let query = `
      SELECT 
        id, visitor_name, mobile, host_employee, host_email, purpose,
        checkin_time, checkout_time, status, created_by,
        COUNT(*) OVER() AS total_count
      FROM vs_visitors
      WHERE 1=1
    `;
    
    const request = sqlPool.request();

    if (date) {
      query += ` AND CAST(checkin_time AS DATE) = @date`;
      request.input('date', sql.Date, date);
    }
    
    if (status) {
      query += ` AND status = @status`;
      request.input('status', sql.NVarChar, status);
    }
    
    if (host_email) {
      query += ` AND host_email = @host_email`;
      request.input('host_email', sql.NVarChar, host_email);
    }
    
    if (search) {
      query += ` AND (visitor_name LIKE @search OR mobile LIKE @search OR host_employee LIKE @search)`;
      request.input('search', sql.NVarChar, `%${search}%`);
    }

    query += ` ORDER BY checkin_time DESC 
               OFFSET @offset ROWS 
               FETCH NEXT @limit ROWS ONLY`;

    request.input('offset', sql.Int, offset);
    request.input('limit', sql.Int, limitNum);

    const result = await request.query(query);
    
    const totalCount = result.recordset.length > 0 ? result.recordset[0].total_count : 0;
    
    // Remove total_count from each row for cleaner response
    const visitors = result.recordset.map(visitor => {
      const { total_count, ...visitorData } = visitor;
      return visitorData;
    });

    res.json({
      visitors,
      pagination: {
        page: pageNum,
        limit: limitNum,
        total: totalCount,
        pages: Math.ceil(totalCount / limitNum)
      }
    });
  } catch (err) {
    console.error('List visitors error:', err);
    res.status(500).json({ 
      error: 'Failed to fetch visitors',
      code: 'FETCH_VISITORS_ERROR'
    });
  }
});

// Export CSV
app.get('/api/admin/export', authenticateToken, requireRole(['admin']), async (req, res) => {
  try {
    const { startDate, endDate } = req.query;
    
    let query = `
      SELECT 
        id, visitor_name, mobile, host_employee, host_email,
        purpose, checkin_time, checkout_time, status, created_by
      FROM vs_visitors
      WHERE 1=1
    `;
    
    const request = sqlPool.request();
    
    if (startDate) {
      query += ` AND CAST(checkin_time AS DATE) >= @startDate`;
      request.input('startDate', sql.Date, startDate);
    }
    
    if (endDate) {
      query += ` AND CAST(checkin_time AS DATE) <= @endDate`;
      request.input('endDate', sql.Date, endDate);
    }
    
    if (!startDate && !endDate) {
      query += ` AND checkin_time >= DATEADD(day, -7, GETDATE())`;
    }
    
    query += ` ORDER BY checkin_time DESC`;
    
    const result = await request.query(query);
    const visitors = result.recordset;

    // Generate CSV
    const headers = [
      'ID', 'Name', 'Mobile', 'Host', 'Email', 
      'Purpose', 'Check-in', 'Check-out', 'Status', 'Created By'
    ];

    const csvRows = [
      headers,
      ...visitors.map(v => [
        v.id,
        `"${(v.visitor_name || '').replace(/"/g, '""')}"`,
        v.mobile || '',
        `"${(v.host_employee || '').replace(/"/g, '""')}"`,
        v.host_email || '',
        `"${(v.purpose || '').replace(/"/g, '""')}"`,
        v.checkin_time ? new Date(v.checkin_time).toISOString() : '',
        v.checkout_time ? new Date(v.checkout_time).toISOString() : '',
        v.status || '',
        v.created_by || ''
      ])
    ];

    const csv = csvRows.map(row => row.join(',')).join('\n');
    const dateRange = startDate || endDate ? 
      `${startDate || 'start'}-to-${endDate || 'today'}` : 
      'last-7-days';
    
    const filename = `Seeds-Visitors-${dateRange}-${new Date().toISOString().split('T')[0]}.csv`;

    res.header('Content-Type', 'text/csv; charset=utf-8');
    res.header('Content-Disposition', `attachment; filename="${filename}"`);
    res.send('\ufeff' + csv); // BOM for Excel UTF-8
  } catch (err) {
    console.error('Export error:', err);
    res.status(500).json({ 
      error: 'Failed to generate export',
      code: 'EXPORT_ERROR'
    });
  }
});

// Get visitor by ID
app.get('/api/visitors/:id', authenticateToken, async (req, res) => {
  try {
    const visitorId = parseInt(req.params.id);
    
    if (isNaN(visitorId)) {
      return res.status(400).json({ 
        error: 'Invalid visitor ID',
        code: 'INVALID_ID'
      });
    }

    const request = sqlPool.request();
    request.input('id', sql.Int, visitorId);
    
    const result = await request.query(`
      SELECT id, visitor_name, mobile, host_employee, host_email, purpose,
             checkin_time, checkout_time, status, created_by,
             photo_base64, qr_code_data
      FROM vs_visitors
      WHERE id = @id
    `);

    if (!result.recordset.length) {
      return res.status(404).json({ 
        error: 'Visitor not found',
        code: 'VISITOR_NOT_FOUND'
      });
    }

    res.json(result.recordset[0]);
  } catch (err) {
    console.error('Get visitor error:', err);
    res.status(500).json({ 
      error: 'Failed to fetch visitor',
      code: 'FETCH_VISITOR_ERROR'
    });
  }
});

// Health check endpoint
app.get('/api/health', async (req, res) => {
  try {
    const dbHealth = sqlPool ? 'connected' : 'disconnected';
    const emailHealth = transporter ? 'ready' : 'not-ready';
    
    const health = {
      status: 'OK',
      timestamp: new Date().toISOString(),
      services: {
        database: dbHealth,
        email: emailHealth,
        jwt: 'active'
      },
      uptime: process.uptime(),
      memory: process.memoryUsage()
    };

    // Test database connection
    if (sqlPool) {
      try {
        await sqlPool.request().query('SELECT 1 AS test');
        health.services.database = 'healthy';
      } catch (err) {
        health.services.database = 'unhealthy';
        health.status = 'DEGRADED';
      }
    }

    res.json(health);
  } catch (err) {
    res.status(500).json({ 
      status: 'ERROR',
      error: err.message,
      timestamp: new Date().toISOString()
    });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? err.message : undefined,
    code: 'INTERNAL_SERVER_ERROR'
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Endpoint not found',
    code: 'NOT_FOUND'
  });
});

// Graceful shutdown
process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

async function gracefulShutdown() {
  console.log('🔄 Shutting down gracefully...');
  
  if (sqlPool) {
    try {
      await sqlPool.close();
      console.log('✅ Database connection closed');
    } catch (err) {
      console.error('❌ Error closing database:', err.message);
    }
  }
  
  transporter.close();
  console.log('✅ Email transporter closed');
  
  process.exit(0);
}

// Start server
const PORT = process.env.PORT || 3032;

initSqlConnection()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`🚀 Visitor Management System running on http://localhost:${PORT}`);
      console.log(`📊 Admin Dashboard: http://localhost:${PORT}/admin.html`);
      console.log(`👤 Admin login: ${process.env.ADMIN_EMAIL || 'admin@seedsfincap.com'}`);
      console.log(`🔐 JWT Secret: ${JWT_SECRET ? 'Configured' : 'Missing!'}`);
      console.log(`📧 Email: ${EMAIL_CONFIG.auth.user ? 'Configured' : 'Missing!'}`);
    });
  })
  .catch(err => {
    console.error('❌ Failed to start server:', err.message);
    process.exit(1);
  });