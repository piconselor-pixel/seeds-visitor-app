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

// Database health check middleware
function databaseHealthCheck(req, res, next) {
  if (!sqlPool || !sqlPool.connected) {
    return res.status(503).json({ 
      error: 'Database connection unavailable',
      code: 'DATABASE_UNAVAILABLE' 
    });
  }
  next();
}

// Apply database health check to all API routes
app.use('/api/*', databaseHealthCheck);

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
    const transaction = new sql.Transaction(sqlPool);
    await transaction.begin();
    
    try {
      // Create users table
      await transaction.request().query(`
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
            created_at DATETIME2 DEFAULT GETDATE(),
            updated_at DATETIME2 DEFAULT GETDATE()
          );
          
          CREATE INDEX idx_users_username ON vs_users(username);
          CREATE INDEX idx_users_email ON vs_users(email);
        END
      `);

      // Create visitors table
      await transaction.request().query(`
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
            created_at DATETIME2 DEFAULT GETDATE(),
            updated_at DATETIME2 DEFAULT GETDATE()
          );
          
          CREATE INDEX idx_visitors_checkin ON vs_visitors(checkin_time);
          CREATE INDEX idx_visitors_status ON vs_visitors(status);
          CREATE INDEX idx_visitors_host_email ON vs_visitors(host_email);
          CREATE INDEX idx_visitors_created_at ON vs_visitors(created_at);
        END
      `);

      // Create audit log table
      await transaction.request().query(`
        IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='vs_audit_log' AND xtype='U')
        BEGIN
          CREATE TABLE vs_audit_log (
            id INT IDENTITY(1,1) PRIMARY KEY,
            user_id INT NULL,
            action NVARCHAR(50) NOT NULL,
            table_name NVARCHAR(50) NOT NULL,
            record_id INT NULL,
            old_data NVARCHAR(MAX) NULL,
            new_data NVARCHAR(MAX) NULL,
            ip_address NVARCHAR(45),
            user_agent NVARCHAR(500),
            created_at DATETIME2 DEFAULT GETDATE()
          );
          
          CREATE INDEX idx_audit_log_created_at ON vs_audit_log(created_at);
          CREATE INDEX idx_audit_log_action ON vs_audit_log(action);
        END
      `);

      // Create default admin user
      const adminHash = await getAdminHash();
      const adminEmail = process.env.ADMIN_EMAIL || 'admin@seedsfincap.com';
      const adminUsername = process.env.ADMIN_USERNAME || 'admin';
      
      await transaction.request()
        .input('adminEmail', sql.NVarChar, adminEmail)
        .input('adminUsername', sql.NVarChar, adminUsername)
        .input('adminHash', sql.NVarChar, adminHash)
        .query(`
          IF NOT EXISTS (SELECT 1 FROM vs_users WHERE username = @adminUsername OR email = @adminEmail)
          BEGIN
            INSERT INTO vs_users (username, email, password, role, is_active)
            VALUES (@adminUsername, @adminEmail, @adminHash, 'admin', 1);
          END
          ELSE
          BEGIN
            UPDATE vs_users 
            SET password = @adminHash, 
                role = 'admin',
                is_active = 1,
                updated_at = GETDATE()
            WHERE username = @adminUsername OR email = @adminEmail;
          END
        `);

      await transaction.commit();
      console.log('✅ Tables created: vs_users, vs_visitors, vs_audit_log');
      
    } catch (error) {
      await transaction.rollback();
      throw error;
    }
  } catch (err) {
    console.error('❌ Table creation error:', err.message);
    throw err;
  }
}

// Audit logging function
async function logAudit(userId, action, tableName, recordId, oldData = null, newData = null, req = null) {
  try {
    await sqlPool.request()
      .input('user_id', sql.Int, userId)
      .input('action', sql.NVarChar, action)
      .input('table_name', sql.NVarChar, tableName)
      .input('record_id', sql.Int, recordId)
      .input('old_data', sql.NVarChar, oldData ? JSON.stringify(oldData) : null)
      .input('new_data', sql.NVarChar, newData ? JSON.stringify(newData) : null)
      .input('ip_address', sql.NVarChar, req ? req.ip : null)
      .input('user_agent', sql.NVarChar, req ? req.get('User-Agent') : null)
      .query(`
        INSERT INTO vs_audit_log (user_id, action, table_name, record_id, old_data, new_data, ip_address, user_agent)
        VALUES (@user_id, @action, @table_name, @record_id, @old_data, @new_data, @ip_address, @user_agent)
      `);
  } catch (error) {
    console.error('❌ Audit logging failed:', error.message);
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

// Rate limiting middleware (basic)
const rateLimitStore = new Map();
function rateLimit(maxRequests = 100, windowMs = 900000) { // 15 minutes default
  return (req, res, next) => {
    const ip = req.ip;
    const now = Date.now();
    
    if (!rateLimitStore.has(ip)) {
      rateLimitStore.set(ip, { count: 1, startTime: now });
    } else {
      const data = rateLimitStore.get(ip);
      
      if (now - data.startTime > windowMs) {
        // Reset window
        data.count = 1;
        data.startTime = now;
      } else {
        data.count++;
        
        if (data.count > maxRequests) {
          return res.status(429).json({
            error: 'Too many requests',
            code: 'RATE_LIMIT_EXCEEDED',
            retryAfter: Math.ceil((data.startTime + windowMs - now) / 1000)
          });
        }
      }
    }
    
    // Cleanup old entries periodically
    if (Math.random() < 0.01) { // 1% chance to cleanup
      for (const [key, value] of rateLimitStore.entries()) {
        if (now - value.startTime > windowMs) {
          rateLimitStore.delete(key);
        }
      }
    }
    
    next();
  };
}

// Apply rate limiting to all API routes
app.use('/api/*', rateLimit(
  parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
  parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 900000
));

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
      SELECT id, username, email, password, role, is_active 
      FROM vs_users 
      WHERE (username = @username OR email = @username) AND is_active = 1
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

    // Update last login time
    await request.input('userId', sql.Int, user.id)
      .query('UPDATE vs_users SET last_login = GETDATE() WHERE id = @userId');

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

    // Log login action
    await logAudit(user.id, 'LOGIN', 'vs_users', user.id, null, null, req);

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
  const transaction = new sql.Transaction(sqlPool);
  
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

    // Validate mobile number if provided
    if (mobile && !/^[0-9]{10}$/.test(mobile)) {
      return res.status(400).json({
        error: 'Mobile number must be 10 digits',
        code: 'INVALID_MOBILE'
      });
    }

    // Start transaction
    await transaction.begin();

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
    const request = new sql.Request(transaction);
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
      OUTPUT INSERTED.id, INSERTED.checkin_time
      VALUES
        (@visitor_name, @mobile, @host_employee, @host_email, @purpose, 
         @photo_base64, @qr_code_data, @created_by)
    `);

    const visitorId = insertResult.recordset[0].id;
    const checkinTime = insertResult.recordset[0].checkin_time;

    // Log the visitor creation
    if (req.user) {
      await logAudit(
        req.user.id, 
        'CREATE_VISITOR', 
        'vs_visitors', 
        visitorId, 
        null, 
        { visitor_name, host_email, purpose }, 
        req
      );
    }

    await transaction.commit();

    // Send email notification (async, don't wait for it)
    try {
      const mailOptions = {
        from: `"${process.env.EMAIL_FROM_NAME || 'Seeds FinCap Visitor System'}" <${EMAIL_CONFIG.auth.user}>`,
        to: host_email,
        subject: `🛡️ New Visitor Check-in: ${visitor_name}`,
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; padding: 20px; border: 1px solid #ddd; border-radius: 10px;">
            <div style="text-align: center; margin-bottom: 20px;">
              <h2 style="color: #007bff; margin: 0;">🔐 New Visitor Alert</h2>
              <p style="color: #666; margin: 5px 0;">Seeds FinCap Visitor Management System</p>
            </div>
            
            <div style="background-color: #f8f9fa; padding: 15px; border-radius: 8px; margin-bottom: 20px;">
              <p style="margin: 0;">A new visitor has checked in to see you.</p>
            </div>
            
            <table style="width: 100%; border-collapse: collapse; border: 1px solid #ddd; margin-bottom: 20px;">
              <tr style="background-color: #007bff; color: white;">
                <th style="padding: 12px; text-align: left; width: 30%;">Field</th>
                <th style="padding: 12px; text-align: left;">Details</th>
              </tr>
              <tr><td style="padding: 10px; border: 1px solid #ddd;"><strong>👤 Visitor Name:</strong></td><td style="padding: 10px; border: 1px solid #ddd;">${visitor_name}</td></tr>
              <tr><td style="padding: 10px; border: 1px solid #ddd;"><strong>📱 Mobile:</strong></td><td style="padding: 10px; border: 1px solid #ddd;">${mobile || 'N/A'}</td></tr>
              <tr><td style="padding: 10px; border: 1px solid #ddd;"><strong>👥 Host Employee:</strong></td><td style="padding: 10px; border: 1px solid #ddd;">${host_employee || 'N/A'}</td></tr>
              <tr><td style="padding: 10px; border: 1px solid #ddd;"><strong>📝 Purpose:</strong></td><td style="padding: 10px; border: 1px solid #ddd;">${purpose}</td></tr>
              <tr><td style="padding: 10px; border: 1px solid #ddd;"><strong>⏰ Check-in Time:</strong></td><td style="padding: 10px; border: 1px solid #ddd;">${new Date(checkinTime).toLocaleString()}</td></tr>
              <tr><td style="padding: 10px; border: 1px solid #ddd;"><strong>🔢 Visitor ID:</strong></td><td style="padding: 10px; border: 1px solid #ddd;">${visitorId}</td></tr>
            </table>
            
            ${photo_base64 ? `
              <div style="margin: 20px 0; text-align: center;">
                <h3 style="color: #333; margin-bottom: 10px;">📸 Visitor Photo</h3>
                <img src="cid:visitor-photo" style="max-width: 300px; border: 2px solid #007bff; border-radius: 8px;" />
              </div>
            ` : ''}
            
            <div style="margin: 20px 0; text-align: center;">
              <h3 style="color: #333; margin-bottom: 10px;">📱 QR Code Pass</h3>
              <p style="margin-bottom: 15px;">Scan this QR code to view visitor details:</p>
              <img src="${qrCodeDataURL}" style="max-width: 200px; border: 2px solid #25D366; border-radius: 8px; padding: 10px; background: white;" />
              <p style="color: #666; font-size: 12px; margin-top: 10px;">Visitor ID: ${qrData.id}</p>
            </div>
            
            <hr style="border: none; border-top: 1px solid #ddd; margin: 20px 0;">
            
            <div style="text-align: center; color: #666; font-size: 12px;">
              <p>This is an automated notification from Seeds FinCap Visitor Management System.</p>
              <p>If you did not expect this visitor, please contact security immediately.</p>
              <p>© ${new Date().getFullYear()} Seeds FinCap. All rights reserved.</p>
            </div>
          </div>
        `,
        attachments: photo_base64 ? [{
          filename: `visitor-${visitorId}-${Date.now()}.jpg`,
          content: Buffer.from(photo_base64.split(',')[1] || photo_base64, 'base64'),
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
        checkinTime: checkinTime,
        visitorId: qrData.id
      }
    });
  } catch (err) {
    await transaction.rollback().catch(() => {});
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
  const transaction = new sql.Transaction(sqlPool);
  
  try {
    const visitorId = parseInt(req.params.id);
    
    if (isNaN(visitorId) || visitorId <= 0) {
      return res.status(400).json({ 
        error: 'Invalid visitor ID',
        code: 'INVALID_ID'
      });
    }

    await transaction.begin();
    
    // First, get the visitor details for audit log
    const getRequest = new sql.Request(transaction);
    getRequest.input('id', sql.Int, visitorId);
    const visitorResult = await getRequest.query(`
      SELECT visitor_name, host_email, status 
      FROM vs_visitors 
      WHERE id = @id
    `);

    if (!visitorResult.recordset.length) {
      await transaction.rollback();
      return res.status(404).json({ 
        error: 'Visitor not found',
        code: 'VISITOR_NOT_FOUND'
      });
    }

    const visitor = visitorResult.recordset[0];
    
    if (visitor.status === 'checked_out') {
      await transaction.rollback();
      return res.status(400).json({ 
        error: 'Visitor already checked out',
        code: 'ALREADY_CHECKED_OUT'
      });
    }

    // Perform checkout
    const request = new sql.Request(transaction);
    request.input('id', sql.Int, visitorId);
    request.input('checkoutBy', sql.NVarChar, req.user.username);

    const result = await request.query(`
      UPDATE vs_visitors
      SET checkout_time = GETDATE(), 
          status = 'checked_out',
          updated_at = GETDATE()
      WHERE id = @id AND status = 'checked_in'
    `);

    if (result.rowsAffected[0] === 0) {
      await transaction.rollback();
      return res.status(404).json({ 
        error: 'Visitor not found or already checked out',
        code: 'VISITOR_NOT_FOUND'
      });
    }

    // Log the checkout action
    await logAudit(
      req.user.id, 
      'CHECKOUT_VISITOR', 
      'vs_visitors', 
      visitorId, 
      { status: 'checked_in' }, 
      { status: 'checked_out', checkout_time: new Date() }, 
      req
    );

    await transaction.commit();

    // Optionally send checkout notification email
    if (visitor.host_email && process.env.SEND_CHECKOUT_EMAILS === 'true') {
      try {
        const mailOptions = {
          from: `"${process.env.EMAIL_FROM_NAME || 'Seeds FinCap Visitor System'}" <${EMAIL_CONFIG.auth.user}>`,
          to: visitor.host_email,
          subject: `✅ Visitor Check-out: ${visitor.visitor_name}`,
          html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; padding: 20px;">
              <h2 style="color: #28a745;">✅ Visitor Checked Out</h2>
              <p><strong>Visitor:</strong> ${visitor.visitor_name}</p>
              <p><strong>Check-out Time:</strong> ${new Date().toLocaleString()}</p>
              <p><strong>Checked out by:</strong> ${req.user.username}</p>
              <hr>
              <p style="color: #666; font-size: 12px;">
                This is an automated notification from Seeds FinCap Visitor Management System.
              </p>
            </div>
          `
        };
        
        transporter.sendMail(mailOptions)
          .catch(err => console.error('Checkout email error:', err.message));
      } catch (emailErr) {
        console.error('Checkout email generation error:', emailErr.message);
      }
    }

    res.json({ 
      success: true,
      message: 'Visitor checked out successfully',
      checkoutTime: new Date().toISOString(),
      visitor: {
        id: visitorId,
        name: visitor.visitor_name
      }
    });
  } catch (err) {
    await transaction.rollback().catch(() => {});
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
        SUM(CASE WHEN status = 'checked_in' THEN 1 ELSE 0 END) AS active_visitors,
        SUM(CASE WHEN status = 'checked_out' THEN 1 ELSE 0 END) AS checked_out_today,
        COUNT(DISTINCT host_email) AS unique_hosts_today,
        MIN(checkin_time) AS first_checkin_today,
        MAX(checkin_time) AS last_checkin_today
      FROM vs_visitors
      WHERE CAST(checkin_time AS DATE) = CAST(GETDATE() AS DATE)
    `);

    const weekStats = await request.query(`
      SELECT 
        COUNT(*) AS total_week,
        COUNT(DISTINCT host_email) AS unique_hosts_week,
        CAST(checkin_time AS DATE) AS date,
        COUNT(*) AS daily_count,
        SUM(CASE WHEN status = 'checked_in' THEN 1 ELSE 0 END) AS active_daily
      FROM vs_visitors
      WHERE checkin_time >= DATEADD(day, -7, GETDATE())
      GROUP BY CAST(checkin_time AS DATE)
      ORDER BY date DESC
    `);

    const monthStats = await request.query(`
      SELECT 
        COUNT(*) AS total_month,
        COUNT(DISTINCT host_email) AS unique_hosts_month,
        DATEPART(WEEK, checkin_time) AS week_number,
        COUNT(*) AS weekly_count
      FROM vs_visitors
      WHERE checkin_time >= DATEADD(month, -1, GETDATE())
      GROUP BY DATEPART(WEEK, checkin_time)
      ORDER BY week_number DESC
    `);

    const allTimeStats = await request.query(`
      SELECT 
        COUNT(*) AS total_all,
        COUNT(DISTINCT host_email) AS total_hosts,
        COUNT(DISTINCT visitor_name) AS unique_visitors,
        MIN(checkin_time) AS first_visitor,
        MAX(checkin_time) AS last_visitor,
        AVG(DATEDIFF(MINUTE, checkin_time, COALESCE(checkout_time, GETDATE()))) AS avg_visit_duration_minutes
      FROM vs_visitors
    `);

    const topHosts = await request.query(`
      SELECT TOP 10 
        host_email,
        COUNT(*) AS visitor_count,
        COUNT(CASE WHEN status = 'checked_in' THEN 1 END) AS active_count
      FROM vs_visitors
      GROUP BY host_email
      ORDER BY visitor_count DESC
    `);

    res.json({
      today: todayStats.recordset[0],
      week: {
        summary: weekStats.recordset[0] || {},
        daily: weekStats.recordset
      },
      month: {
        summary: monthStats.recordset[0] || {},
        weekly: monthStats.recordset
      },
      allTime: allTimeStats.recordset[0],
      topHosts: topHosts.recordset,
      timestamp: new Date().toISOString()
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
      host_employee,
      page = 1, 
      limit = 50,
      search,
      sortBy = 'checkin_time',
      sortOrder = 'DESC'
    } = req.query;

    const pageNum = Math.max(1, parseInt(page));
    const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
    const offset = (pageNum - 1) * limitNum;

    // Validate sort columns to prevent SQL injection
    const validSortColumns = ['checkin_time', 'checkout_time', 'visitor_name', 'host_employee', 'host_email', 'status'];
    const sortColumn = validSortColumns.includes(sortBy) ? sortBy : 'checkin_time';
    const order = sortOrder.toUpperCase() === 'ASC' ? 'ASC' : 'DESC';

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
    
    if (host_employee) {
      query += ` AND host_employee LIKE @host_employee`;
      request.input('host_employee', sql.NVarChar, `%${host_employee}%`);
    }
    
    if (search) {
      query += ` AND (
        visitor_name LIKE @search 
        OR mobile LIKE @search 
        OR host_employee LIKE @search
        OR host_email LIKE @search
        OR purpose LIKE @search
      )`;
      request.input('search', sql.NVarChar, `%${search}%`);
    }

    query += ` ORDER BY ${sortColumn} ${order}
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
        pages: Math.ceil(totalCount / limitNum),
        hasNext: (pageNum * limitNum) < totalCount,
        hasPrev: pageNum > 1
      },
      filters: {
        date,
        status,
        host_email,
        host_employee,
        search,
        sortBy: sortColumn,
        sortOrder: order
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
    const { startDate, endDate, format = 'csv' } = req.query;
    
    let query = `
      SELECT 
        id, visitor_name, mobile, host_employee, host_email,
        purpose, checkin_time, checkout_time, status, created_by,
        DATEDIFF(MINUTE, checkin_time, COALESCE(checkout_time, GETDATE())) AS duration_minutes
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

    if (format === 'json') {
      // Return JSON format
      res.json({
        exportDate: new Date().toISOString(),
        recordCount: visitors.length,
        data: visitors
      });
    } else {
      // Return CSV format
      const headers = [
        'ID', 'Name', 'Mobile', 'Host', 'Email', 
        'Purpose', 'Check-in', 'Check-out', 'Status', 'Created By', 'Duration (minutes)'
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
          v.created_by || '',
          v.duration_minutes || ''
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
    }
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
    
    if (isNaN(visitorId) || visitorId <= 0) {
      return res.status(400).json({ 
        error: 'Invalid visitor ID',
        code: 'INVALID_ID'
      });
    }

    const request = sqlPool.request();
    request.input('id', sql.Int, visitorId);
    
    const result = await request.query(`
      SELECT 
        id, visitor_name, mobile, host_employee, host_email, purpose,
        checkin_time, checkout_time, status, created_by,
        photo_base64, qr_code_data,
        DATEDIFF(MINUTE, checkin_time, COALESCE(checkout_time, GETDATE())) AS duration_minutes
      FROM vs_visitors
      WHERE id = @id
    `);

    if (!result.recordset.length) {
      return res.status(404).json({ 
        error: 'Visitor not found',
        code: 'VISITOR_NOT_FOUND'
      });
    }

    const visitor = result.recordset[0];
    
    // Don't send photo_base64 in list view unless specifically requested
    if (!req.query.includePhoto) {
      delete visitor.photo_base64;
    }

    res.json(visitor);
  } catch (err) {
    console.error('Get visitor error:', err);
    res.status(500).json({ 
      error: 'Failed to fetch visitor',
      code: 'FETCH_VISITOR_ERROR'
    });
  }
});

// Get visitor photo by ID
app.get('/api/visitors/:id/photo', authenticateToken, async (req, res) => {
  try {
    const visitorId = parseInt(req.params.id);
    
    if (isNaN(visitorId) || visitorId <= 0) {
      return res.status(400).json({ 
        error: 'Invalid visitor ID',
        code: 'INVALID_ID'
      });
    }

    const request = sqlPool.request();
    request.input('id', sql.Int, visitorId);
    
    const result = await request.query(`
      SELECT photo_base64
      FROM vs_visitors
      WHERE id = @id
    `);

    if (!result.recordset.length || !result.recordset[0].photo_base64) {
      return res.status(404).json({ 
        error: 'Visitor photo not found',
        code: 'PHOTO_NOT_FOUND'
      });
    }

    const photoBase64 = result.recordset[0].photo_base64;
    
    // Determine content type
    let contentType = 'image/jpeg';
    if (photoBase64.startsWith('data:image/png')) {
      contentType = 'image/png';
    } else if (photoBase64.startsWith('data:image/jpeg') || photoBase64.startsWith('data:image/jpg')) {
      contentType = 'image/jpeg';
    }
    
    // Extract base64 data
    const base64Data = photoBase64.replace(/^data:image\/\w+;base64,/, '');
    const imageBuffer = Buffer.from(base64Data, 'base64');
    
    res.writeHead(200, {
      'Content-Type': contentType,
      'Content-Length': imageBuffer.length,
      'Cache-Control': 'private, max-age=3600'
    });
    res.end(imageBuffer);
  } catch (err) {
    console.error('Get visitor photo error:', err);
    res.status(500).json({ 
      error: 'Failed to fetch visitor photo',
      code: 'FETCH_PHOTO_ERROR'
    });
  }
});

// Update visitor
app.put('/api/visitors/:id', authenticateToken, requireRole(['admin', 'reception']), async (req, res) => {
  const transaction = new sql.Transaction(sqlPool);
  
  try {
    const visitorId = parseInt(req.params.id);
    
    if (isNaN(visitorId) || visitorId <= 0) {
      return res.status(400).json({ 
        error: 'Invalid visitor ID',
        code: 'INVALID_ID'
      });
    }

    const { 
      visitor_name, 
      mobile, 
      host_employee, 
      host_email, 
      purpose 
    } = req.body;

    // Get old data for audit log
    await transaction.begin();
    const getRequest = new sql.Request(transaction);
    getRequest.input('id', sql.Int, visitorId);
    const oldResult = await getRequest.query(`
      SELECT visitor_name, mobile, host_employee, host_email, purpose
      FROM vs_visitors
      WHERE id = @id
    `);

    if (!oldResult.recordset.length) {
      await transaction.rollback();
      return res.status(404).json({ 
        error: 'Visitor not found',
        code: 'VISITOR_NOT_FOUND'
      });
    }

    const oldData = oldResult.recordset[0];

    // Update visitor
    const updateRequest = new sql.Request(transaction);
    updateRequest.input('id', sql.Int, visitorId);
    updateRequest.input('visitor_name', sql.NVarChar, visitor_name || oldData.visitor_name);
    updateRequest.input('mobile', sql.NVarChar, mobile || oldData.mobile);
    updateRequest.input('host_employee', sql.NVarChar, host_employee || oldData.host_employee);
    updateRequest.input('host_email', sql.NVarChar, host_email || oldData.host_email);
    updateRequest.input('purpose', sql.NVarChar, purpose || oldData.purpose);

    const result = await updateRequest.query(`
      UPDATE vs_visitors
      SET 
        visitor_name = @visitor_name,
        mobile = @mobile,
        host_employee = @host_employee,
        host_email = @host_email,
        purpose = @purpose,
        updated_at = GETDATE()
      WHERE id = @id
    `);

    if (result.rowsAffected[0] === 0) {
      await transaction.rollback();
      return res.status(404).json({ 
        error: 'Visitor not found',
        code: 'VISITOR_NOT_FOUND'
      });
    }

    // Log the update
    const newData = {
      visitor_name: visitor_name || oldData.visitor_name,
      mobile: mobile || oldData.mobile,
      host_employee: host_employee || oldData.host_employee,
      host_email: host_email || oldData.host_email,
      purpose: purpose || oldData.purpose
    };

    await logAudit(
      req.user.id, 
      'UPDATE_VISITOR', 
      'vs_visitors', 
      visitorId, 
      oldData, 
      newData, 
      req
    );

    await transaction.commit();

    res.json({ 
      success: true,
      message: 'Visitor updated successfully',
      visitorId
    });
  } catch (err) {
    await transaction.rollback().catch(() => {});
    console.error('Update visitor error:', err);
    res.status(500).json({ 
      error: 'Failed to update visitor',
      code: 'UPDATE_VISITOR_ERROR'
    });
  }
});

// Health check endpoint with detailed diagnostics
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
        const dbResult = await dbRequest.query(`
          SELECT 
            DB_NAME() AS database_name,
            COUNT(*) AS active_connections,
            GETDATE() AS server_time,
            (SELECT COUNT(*) FROM vs_visitors) AS total_visitors,
            (SELECT COUNT(*) FROM vs_users) AS total_users
        `);
        
        health.database = {
          status: 'healthy',
          ...dbResult.recordset[0],
          poolStats: {
            size: sqlPool.pool.size,
            available: sqlPool.pool.available,
            borrowed: sqlPool.pool.borrowed
          }
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

// Database diagnostics endpoint
app.get('/api/database/diagnostics', authenticateToken, requireRole(['admin']), async (req, res) => {
  try {
    const request = sqlPool.request();
    
    const [tables, connections, performance] = await Promise.all([
      request.query(`
        SELECT 
          t.name AS table_name,
          p.rows AS row_count,
          SUM(a.total_pages) * 8 AS total_space_kb,
          SUM(a.used_pages) * 8 AS used_space_kb
        FROM sys.tables t
        INNER JOIN sys.partitions p ON t.object_id = p.object_id
        INNER JOIN sys.allocation_units a ON p.partition_id = a.container_id
        WHERE t.name IN ('vs_visitors', 'vs_users', 'vs_audit_log')
        GROUP BY t.name, p.rows
        ORDER BY t.name
      `),
      request.query(`
        SELECT 
          COUNT(*) AS total_connections,
          COUNT(CASE WHEN status = 'sleeping' THEN 1 END) AS idle_connections,
          COUNT(CASE WHEN status = 'running' THEN 1 END) AS active_connections
        FROM sys.dm_exec_connections
        WHERE session_id > 50
      `),
      request.query(`
        SELECT 
          (SELECT COUNT(*) FROM vs_visitors WHERE DATEDIFF(HOUR, checkin_time, GETDATE()) < 24) AS visitors_last_24h,
          (SELECT COUNT(*) FROM vs_visitors WHERE status = 'checked_in') AS active_visitors_now,
          (SELECT AVG(DATEDIFF(MINUTE, checkin_time, checkout_time)) FROM vs_visitors WHERE checkout_time IS NOT NULL) AS avg_visit_duration
      `)
    ]);

    res.json({
      tables: tables.recordset,
      connections: connections.recordset[0],
      performance: performance.recordset[0],
      serverInfo: {
        version: 'SQL Server',
        currentTime: new Date().toISOString(),
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
      }
    });
  } catch (err) {
    console.error('Database diagnostics error:', err);
    res.status(500).json({ 
      error: 'Failed to fetch database diagnostics',
      code: 'DIAGNOSTICS_ERROR'
    });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', {
    message: err.message,
    stack: err.stack,
    path: req.path,
    method: req.method,
    ip: req.ip,
    timestamp: new Date().toISOString()
  });

  res.status(500).json({
    error: 'Internal server error',
    code: 'INTERNAL_SERVER_ERROR',
    requestId: req.headers['x-request-id'] || Math.random().toString(36).substr(2, 9),
    timestamp: new Date().toISOString()
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Endpoint not found',
    code: 'NOT_FOUND',
    path: req.path,
    method: req.method
  });
});

// Graceful shutdown
async function gracefulShutdown(signal) {
  console.log(`\n${signal} received. Starting graceful shutdown...`);
  
  const shutdownPromises = [];
  
  // Close database connections
  if (sqlPool) {
    shutdownPromises.push(
      sqlPool.close().then(() => {
        console.log('✅ Database connections closed');
      }).catch(err => {
        console.error('❌ Error closing database connections:', err.message);
      })
    );
  }
  
  // Close email transporter
  if (transporter) {
    transporter.close();
    console.log('✅ Email transporter closed');
  }
  
  // Wait for all shutdown operations
  await Promise.allSettled(shutdownPromises);
  
  console.log('👋 Graceful shutdown completed');
  process.exit(0);
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
  gracefulShutdown('UNCAUGHT_EXCEPTION');
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

// Start server
const PORT = process.env.PORT || 3032;

initSqlConnection()
  .then(() => {
    const server = app.listen(PORT, () => {
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

    // Handle server errors
    server.on('error', (error) => {
      if (error.code === 'EADDRINUSE') {
        console.error(`❌ Port ${PORT} is already in use`);
        process.exit(1);
      } else {
        console.error('❌ Server error:', error);
      }
    });
  })
  .catch(err => {
    console.error('❌ Failed to start server:', err.message);
    process.exit(1);
  });

// Export app for testing
module.exports = app;