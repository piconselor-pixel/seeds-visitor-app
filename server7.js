const express = require('express');
const sql = require('mssql');
const nodemailer = require('nodemailer');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const QRCode = require('qrcode');
const bodyParser = require('body-parser');
const path = require('path');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors({
  origin: process.env.CORS_ORIGIN || '*',
  credentials: process.env.CORS_CREDENTIALS === 'true' || false
}));
app.use(bodyParser.json({ limit: process.env.MAX_FILE_SIZE_MB || '50mb' }));
app.use(bodyParser.urlencoded({ 
  limit: process.env.MAX_FIELD_SIZE_MB || '50mb', 
  extended: true 
}));
app.use(express.static('public'));

// Environment variable validation
const requiredEnvVars = [
  'DB_USER', 'DB_PASSWORD', 'DB_SERVER', 'DB_NAME', 'DB_PORT',
  'JWT_SECRET', 'EMAIL_USER', 'EMAIL_PASS'
];

const missingVars = requiredEnvVars.filter(varName => !process.env[varName]);
if (missingVars.length > 0 && process.env.NODE_ENV !== 'test') {
  console.error('❌ Missing required environment variables:', missingVars);
  process.exit(1);
}

// Enhanced SQL Server Connection Config
const SQL_CONFIG = {
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  server: process.env.DB_SERVER,
  port: parseInt(process.env.DB_PORT),
  database: process.env.DB_NAME,
  options: {
    encrypt: process.env.DB_ENCRYPT === 'true' || false,
    trustServerCertificate: process.env.DB_TRUST_SERVER_CERTIFICATE === 'true' || true,
    enableArithAbort: true,
    connectTimeout: parseInt(process.env.DB_CONNECT_TIMEOUT) || 30000,
    requestTimeout: parseInt(process.env.DB_REQUEST_TIMEOUT) || 30000
  },
  pool: {
    max: parseInt(process.env.DB_POOL_MAX) || 10,
    min: parseInt(process.env.DB_POOL_MIN) || 0,
    idleTimeoutMillis: parseInt(process.env.DB_POOL_IDLE_TIMEOUT) || 30000,
    acquireTimeoutMillis: parseInt(process.env.DB_POOL_ACQUIRE_TIMEOUT) || 30000
  },
  connectionTimeout: parseInt(process.env.DB_CONNECTION_TIMEOUT) || 15000
};

// Enhanced Email Config
const EMAIL_CONFIG = {
  host: process.env.EMAIL_HOST || 'smtp.gmail.com',
  port: parseInt(process.env.EMAIL_PORT) || 587,
  secure: process.env.EMAIL_SECURE === 'true' || false,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  },
  tls: {
    rejectUnauthorized: process.env.NODE_ENV === 'production'
  }
};

const JWT_SECRET = process.env.JWT_SECRET;

const transporter = nodemailer.createTransport(EMAIL_CONFIG);

let sqlPool;

// Enhanced database connection with retry and exponential backoff
async function connectWithRetry(maxRetries = 5, initialDelay = 5000) {
  let delay = initialDelay;
  
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      console.log(`🔌 Database connection attempt ${attempt}/${maxRetries}...`);
      sqlPool = await sql.connect(SQL_CONFIG);
      
      // Test connection with a simple query
      await sqlPool.request().query('SELECT @@VERSION AS version');
      console.log('✅ SQL Server Connected - VisitorDB');
      return sqlPool;
    } catch (err) {
      console.error(`❌ Connection attempt ${attempt} failed:`, err.message);
      
      if (attempt === maxRetries) {
        throw new Error(`Failed to connect to database after ${maxRetries} attempts: ${err.message}`);
      }
      
      console.log(`⏳ Waiting ${delay/1000} seconds before next attempt...`);
      await new Promise(resolve => setTimeout(resolve, delay));
      
      // Exponential backoff
      delay = Math.min(delay * 1.5, 30000); // Max 30 seconds delay
    }
  }
}

// Init DB + tables
async function initSqlConnection() {
  try {
    await connectWithRetry();
    
    // Verify email connection
    await transporter.verify().then(() => {
      console.log('✅ Email server is ready to send messages');
    }).catch(err => {
      console.warn('⚠️ Email verification failed:', err.message);
    });

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
    // Check and create users table with proper column checking
    const checkUsersTable = await sqlPool.request().query(`
      IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='vs_users' AND xtype='U')
      BEGIN
        CREATE TABLE vs_users (
          id INT IDENTITY(1,1) PRIMARY KEY,
          username NVARCHAR(50) UNIQUE NOT NULL,
          email NVARCHAR(100) UNIQUE NOT NULL,
          password NVARCHAR(255) NOT NULL,
          role NVARCHAR(20) DEFAULT 'reception',
          is_active BIT DEFAULT 1,
          last_login DATETIME2 NULL,
          created_at DATETIME2 DEFAULT GETDATE()
        );
        
        CREATE INDEX idx_users_username ON vs_users(username);
        CREATE INDEX idx_users_email ON vs_users(email);
        
        PRINT '✅ vs_users table created';
      END
      ELSE
      BEGIN
        PRINT 'ℹ️ vs_users table already exists';
        
        -- Add missing columns if they don't exist
        IF NOT EXISTS (SELECT * FROM sys.columns WHERE object_id = OBJECT_ID('vs_users') AND name = 'is_active')
        BEGIN
          ALTER TABLE vs_users ADD is_active BIT DEFAULT 1;
          PRINT '✅ Added is_active column to vs_users';
        END
        
        IF NOT EXISTS (SELECT * FROM sys.columns WHERE object_id = OBJECT_ID('vs_users') AND name = 'last_login')
        BEGIN
          ALTER TABLE vs_users ADD last_login DATETIME2 NULL;
          PRINT '✅ Added last_login column to vs_users';
        END
      END
    `);

    // Check and create visitors table
    const checkVisitorsTable = await sqlPool.request().query(`
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
        );
        
        CREATE INDEX idx_visitors_checkin ON vs_visitors(checkin_time);
        CREATE INDEX idx_visitors_status ON vs_visitors(status);
        CREATE INDEX idx_visitors_host_email ON vs_visitors(host_email);
        CREATE INDEX idx_visitors_created_at ON vs_visitors(created_at);
        
        PRINT '✅ vs_visitors table created';
      END
      ELSE
      BEGIN
        PRINT 'ℹ️ vs_visitors table already exists';
        
        -- Check for missing columns and add them
        DECLARE @ColumnName NVARCHAR(100);
        
        -- Check for qr_code_data column
        IF NOT EXISTS (SELECT * FROM sys.columns WHERE object_id = OBJECT_ID('vs_visitors') AND name = 'qr_code_data')
        BEGIN
          ALTER TABLE vs_visitors ADD qr_code_data NVARCHAR(MAX);
          PRINT '✅ Added qr_code_data column to vs_visitors';
        END
        
        -- Check for photo_base64 column
        IF NOT EXISTS (SELECT * FROM sys.columns WHERE object_id = OBJECT_ID('vs_visitors') AND name = 'photo_base64')
        BEGIN
          ALTER TABLE vs_visitors ADD photo_base64 NVARCHAR(MAX);
          PRINT '✅ Added photo_base64 column to vs_visitors';
        END
        
        -- Check for created_by column
        IF NOT EXISTS (SELECT * FROM sys.columns WHERE object_id = OBJECT_ID('vs_visitors') AND name = 'created_by')
        BEGIN
          ALTER TABLE vs_visitors ADD created_by NVARCHAR(50);
          PRINT '✅ Added created_by column to vs_visitors';
        END
        
        -- Check for created_at column
        IF NOT EXISTS (SELECT * FROM sys.columns WHERE object_id = OBJECT_ID('vs_visitors') AND name = 'created_at')
        BEGIN
          ALTER TABLE vs_visitors ADD created_at DATETIME2 DEFAULT GETDATE();
          PRINT '✅ Added created_at column to vs_visitors';
        END
      END
    `);

    // Create default admin user
    const adminHash = await getAdminHash();
    const adminEmail = process.env.ADMIN_EMAIL || 'admin@seedsfincap.com';
    const adminUsername = process.env.ADMIN_USERNAME || 'admin';
    
    const adminRequest = sqlPool.request();
    adminRequest.input('adminEmail', sql.NVarChar, adminEmail);
    adminRequest.input('adminUsername', sql.NVarChar, adminUsername);
    adminRequest.input('adminHash', sql.NVarChar, adminHash);
    
    const adminResult = await adminRequest.query(`
      IF NOT EXISTS (SELECT 1 FROM vs_users WHERE username = @adminUsername OR email = @adminEmail)
      BEGIN
        INSERT INTO vs_users (username, email, password, role, is_active)
        VALUES (@adminUsername, @adminEmail, @adminHash, 'admin', 1);
        PRINT '✅ Admin user created';
      END
      ELSE
      BEGIN
        UPDATE vs_users 
        SET password = @adminHash, 
            role = 'admin',
            is_active = 1
        WHERE username = @adminUsername OR email = @adminEmail;
        PRINT '✅ Admin user updated';
      END
    `);

    console.log('✅ Tables checked/created: vs_users, vs_visitors');
    
  } catch (err) {
    console.error('❌ Table creation error:', err.message);
    // Try to continue even if table modification fails
    if (err.message.includes('Invalid column name')) {
      console.log('⚠️ Warning: Some columns may already exist. Continuing...');
    } else {
      throw err;
    }
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
        requiredRoles: roles,
        code: 'INSUFFICIENT_PERMISSIONS'
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
      SELECT id, username, email, password, role, COALESCE(is_active, 1) as is_active 
      FROM vs_users 
      WHERE (username = @username OR email = @username)
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
    
    // Check if user is active
    if (user.is_active === 0 || user.is_active === false) {
      return res.status(403).json({ 
        error: 'Account is disabled',
        code: 'ACCOUNT_DISABLED'
      });
    }

    const passwordValid = await bcrypt.compare(password, user.password);

    if (!passwordValid) {
      return res.status(401).json({ 
        error: 'Invalid credentials',
        code: 'INVALID_CREDENTIALS'
      });
    }

    // Update last login time if column exists
    try {
      await request.input('userId', sql.Int, user.id)
        .query('UPDATE vs_users SET last_login = GETDATE() WHERE id = @userId');
    } catch (updateErr) {
      // Ignore error if last_login column doesn't exist
      if (!updateErr.message.includes('Invalid column name')) {
        console.warn('⚠️ Could not update last login:', updateErr.message);
      }
    }

    const token = jwt.sign(
      { 
        id: user.id, 
        username: user.username, 
        email: user.email,
        role: user.role 
      },
      JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '24h' }
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

// Health check endpoint
app.get('/api/health', async (req, res) => {
  try {
    const health = {
      status: 'OK',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      services: {},
      database: {},
      environment: process.env.NODE_ENV || 'development'
    };

    // Database health check
    if (sqlPool && sqlPool.connected) {
      try {
        const dbRequest = sqlPool.request();
        const dbResult = await dbRequest.query('SELECT 1 AS test');
        health.database = {
          status: 'healthy',
          connected: true
        };
      } catch (dbErr) {
        health.database = {
          status: 'unhealthy',
          error: dbErr.message
        };
        health.status = 'DEGRADED';
      }
    } else {
      health.database = { status: 'disconnected' };
      health.status = 'DEGRADED';
    }

    // Email service health check
    try {
      await transporter.verify();
      health.services.email = 'healthy';
    } catch (emailErr) {
      health.services.email = 'unhealthy';
      health.status = 'DEGRADED';
    }

    // JWT service
    health.services.jwt = 'active';

    res.json(health);
  } catch (err) {
    res.status(500).json({ 
      status: 'ERROR',
      error: err.message,
      timestamp: new Date().toISOString()
    });
  }
});

// Database health middleware for all other API routes
app.use('/api', (req, res, next) => {
  // Skip health check for /api/health endpoint
  if (req.path === '/health' || req.path === '/login') {
    return next();
  }
  
  if (!sqlPool || !sqlPool.connected) {
    return res.status(503).json({ 
      error: 'Database connection unavailable',
      code: 'DATABASE_UNAVAILABLE' 
    });
  }
  next();
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
    
    // Handle optional columns
    if (photo_base64) {
      request.input('photo_base64', sql.NVarChar, photo_base64);
    }
    
    request.input('qr_code_data', sql.NVarChar, JSON.stringify(qrData));
    request.input('created_by', sql.NVarChar, req.user?.username || 'system');

    // Build dynamic INSERT query based on available columns
    let insertQuery = `
      INSERT INTO vs_visitors
        (visitor_name, mobile, host_employee, host_email, purpose, qr_code_data, created_by`;
    
    if (photo_base64) {
      insertQuery += `, photo_base64`;
    }
    
    insertQuery += `)
      OUTPUT INSERTED.id
      VALUES
        (@visitor_name, @mobile, @host_employee, @host_email, @purpose, @qr_code_data, @created_by`;
    
    if (photo_base64) {
      insertQuery += `, @photo_base64`;
    }
    
    insertQuery += `)`;

    const insertResult = await request.query(insertQuery);
    const visitorId = insertResult.recordset[0].id;

    // Send email notification (async, don't wait for it)
    try {
      const mailOptions = {
        from: `"${process.env.EMAIL_FROM_NAME || 'Seeds FinCap Visitor System'}" <${EMAIL_CONFIG.auth.user}>`,
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
        checkin_time, checkout_time, status, created_by
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

    // Get total count first
    const countQuery = query.replace('SELECT id, visitor_name, mobile, host_employee, host_email, purpose, checkin_time, checkout_time, status, created_by', 'SELECT COUNT(*) as total_count');
    const countResult = await request.query(countQuery);
    const totalCount = countResult.recordset[0].total_count || 0;

    // Add pagination to main query
    query += ` ORDER BY checkin_time DESC 
               OFFSET @offset ROWS 
               FETCH NEXT @limit ROWS ONLY`;

    request.input('offset', sql.Int, offset);
    request.input('limit', sql.Int, limitNum);

    const result = await request.query(query);

    res.json({
      visitors: result.recordset,
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
    
    // Check which columns exist first
    const columnCheck = await request.query(`
      SELECT COLUMN_NAME 
      FROM INFORMATION_SCHEMA.COLUMNS 
      WHERE TABLE_NAME = 'vs_visitors' 
      AND COLUMN_NAME IN ('photo_base64', 'qr_code_data')
    `);
    
    const availableColumns = columnCheck.recordset.map(row => row.COLUMN_NAME);
    
    // Build query based on available columns
    let selectColumns = 'id, visitor_name, mobile, host_employee, host_email, purpose, checkin_time, checkout_time, status, created_by';
    
    if (availableColumns.includes('photo_base64')) {
      selectColumns += ', photo_base64';
    }
    
    if (availableColumns.includes('qr_code_data')) {
      selectColumns += ', qr_code_data';
    }
    
    const result = await request.query(`
      SELECT ${selectColumns}
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
      console.log(`
🚀 SEEDS VISITOR MANAGEMENT SYSTEM
==================================
✅ Server running on: http://localhost:${PORT}
✅ Database: ${process.env.DB_SERVER}:${process.env.DB_PORT}/${process.env.DB_NAME}
✅ Email: ${EMAIL_CONFIG.auth.user ? 'Configured' : 'Not configured'}
✅ Admin: ${process.env.ADMIN_EMAIL || 'admin@seedsfincap.com'}
✅ Environment: ${process.env.NODE_ENV || 'development'}
==================================
📊 Dashboard: http://localhost:${PORT}/admin.html
👤 Reception: http://localhost:${PORT}/index.html
🔗 API Base: http://localhost:${PORT}/api
==================================
      `);
    });
  })
  .catch(err => {
    console.error('❌ Failed to start server:', err.message);
    process.exit(1);
  });