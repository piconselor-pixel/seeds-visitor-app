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

// Seeds FinCap branding
const SEEDS_BRANDING = {
  logoUrl: 'https://cdn.prod.website-files.com/65b65b84c3edfa5897cdfb0b/65d10f4087845b6e392e1dcd_seeds.png',
  companyName: 'Seeds Fincap Pvt. Ltd.',
  primaryColor: '#2E5BFF', // Seeds blue
  secondaryColor: '#00D4AA', // Seeds green
  textColor: '#2E384D',
  lightBg: '#F8F9FC',
  borderColor: '#E0E6FF'
};

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
    console.error('❌ Table creation error:', err);
    // Try to continue even if table modification fails
    if (err.message && err.message.includes('Invalid column name')) {
      console.log('⚠️ Warning: Some columns may already exist. Continuing...');
    } else {
      throw err;
    }
  }
}

// Generate QR code as base64 and also as buffer for email attachment
async function generateQRCodeWithMultipleFormats(qrData) {
  try {
    // Generate QR code as base64 data URL
    const qrCodeDataURL = await QRCode.toDataURL(JSON.stringify(qrData), {
      width: 400,
      margin: 2,
      color: {
        dark: '#000000',
        light: '#FFFFFF'
      }
    });
    
    // Also generate as buffer for email attachment
    const qrCodeBuffer = await QRCode.toBuffer(JSON.stringify(qrData), {
      width: 400,
      margin: 2,
      color: {
        dark: '#000000',
        light: '#FFFFFF'
      }
    });
    
    return {
      dataURL: qrCodeDataURL,
      buffer: qrCodeBuffer,
      base64: qrCodeDataURL.split(',')[1] // Extract base64 without data URL prefix
    };
  } catch (error) {
    console.error('❌ QR Code generation error:', error);
    throw error;
  }
}

// Helper function to calculate visit duration
function calculateVisitDuration(checkinTime, checkoutTime) {
  const checkin = new Date(checkinTime);
  const checkout = new Date(checkoutTime);
  const durationMs = checkout - checkin;
  
  const hours = Math.floor(durationMs / (1000 * 60 * 60));
  const minutes = Math.floor((durationMs % (1000 * 60 * 60)) / (1000 * 60));
  
  if (hours > 0) {
    return `${hours} hour${hours > 1 ? 's' : ''} ${minutes} minute${minutes > 1 ? 's' : ''}`;
  }
  return `${minutes} minute${minutes > 1 ? 's' : ''}`;
}

// Helper function to format date in GMT+5:30 (Indian Standard Time)
function formatDateTimeIST(dateTime) {
  const date = new Date(dateTime);
  
  // Convert to IST (GMT+5:30)
  const istOffset = 5.5 * 60 * 60 * 1000; // 5.5 hours in milliseconds
  const istTime = new Date(date.getTime() + istOffset);
  
  // Format date
  const optionsDate = { 
    weekday: 'long',
    year: 'numeric', 
    month: 'long', 
    day: 'numeric' 
  };
  
  // Format time
  const optionsTime = {
    hour: '2-digit',
    minute: '2-digit',
    hour12: true,
    timeZone: 'Asia/Kolkata'
  };
  
  const dateStr = date.toLocaleDateString('en-IN', optionsDate);
  const timeStr = date.toLocaleTimeString('en-IN', optionsTime);
  
  return {
    fullDateTime: `${dateStr} at ${timeStr} IST`,
    dateOnly: dateStr,
    timeOnly: timeStr,
    dateTime: `${dateStr} ${timeStr}`,
    timestamp: date.toLocaleString('en-IN', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      hour12: true,
      timeZone: 'Asia/Kolkata'
    })
  };
}

// Generate beautiful email HTML template WITH EMBEDDED QR CODE AND BEAUTIFUL TABLES
function generateVisitorEmailHTML(visitorData, hasPhoto = false, serverUrl = '') {
  // Format times in IST (GMT+5:30)
  const checkinTimeFormatted = formatDateTimeIST(visitorData.checkin_time || new Date());
  const currentTimeFormatted = formatDateTimeIST(new Date());

  // Beautiful table for visitor details
  const visitorTable = `
    <div class="details-table-container">
      <h3 class="table-title">
        <span style="font-size: 20px;">📋</span> Visitor Information Summary
      </h3>
      <table class="details-table">
        <thead>
          <tr>
            <th colspan="2" style="background: ${SEEDS_BRANDING.primaryColor}; color: white; text-align: center; font-size: 16px; padding: 15px;">
              Visitor Details
            </th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td class="table-label">Visitor Name</td>
            <td class="table-value highlight">${visitorData.visitor_name}</td>
          </tr>
          <tr>
            <td class="table-label">Mobile Number</td>
            <td class="table-value">${visitorData.mobile || 'Not provided'}</td>
          </tr>
          <tr>
            <td class="table-label">Host Employee</td>
            <td class="table-value">${visitorData.host_employee || 'Not specified'}</td>
          </tr>
          <tr>
            <td class="table-label">Host Email</td>
            <td class="table-value email-cell">${visitorData.host_email}</td>
          </tr>
          <tr>
            <td class="table-label">Check-in Time</td>
            <td class="table-value time-cell">
              ${checkinTimeFormatted.fullDateTime}
              <br><small style="color: #94A3B8;">(GMT+5:30 - Indian Standard Time)</small>
            </td>
          </tr>
          <tr>
            <td class="table-label">Purpose of Visit</td>
            <td class="table-value purpose-cell">${visitorData.purpose}</td>
          </tr>
          <tr>
            <td class="table-label">Visitor ID</td>
            <td class="table-value id-cell">
              <span class="badge">${visitorData.qr_id || visitorData.visitor_id || 'N/A'}</span>
            </td>
          </tr>
          <tr>
            <td class="table-label">Visit Status</td>
            <td class="table-value">
              <span class="status-badge checked-in">Checked In</span>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  `;

  // Table for visit timeline
  const timelineTable = `
    <div class="timeline-container">
      <h3 class="table-title">
        <span style="font-size: 20px;">⏰</span> Visit Timeline
      </h3>
      <table class="timeline-table">
        <thead>
          <tr>
            <th>Step</th>
            <th>Status</th>
            <th>Time (IST)</th>
            <th>Duration</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>Registration</td>
            <td><span class="status-badge completed">Completed</span></td>
            <td>${checkinTimeFormatted.timeOnly}</td>
            <td>--</td>
          </tr>
          <tr>
            <td>Host Notification</td>
            <td><span class="status-badge in-progress">In Progress</span></td>
            <td>${currentTimeFormatted.timeOnly}</td>
            <td>0 mins</td>
          </tr>
          <tr>
            <td>Meeting</td>
            <td><span class="status-badge pending">Pending</span></td>
            <td>--</td>
            <td>--</td>
          </tr>
          <tr>
            <td>Check-out</td>
            <td><span class="status-badge pending">Pending</span></td>
            <td>--</td>
            <td>--</td>
          </tr>
        </tbody>
      </table>
    </div>
  `;

  return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>New Visitor Alert - Seeds FinCap</title>
      <style>
        * {
          margin: 0;
          padding: 0;
          box-sizing: border-box;
        }
        
        body {
          font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
          line-height: 1.6;
          color: ${SEEDS_BRANDING.textColor};
          background-color: #f5f7fa;
          -webkit-font-smoothing: antialiased;
          -moz-osx-font-smoothing: grayscale;
        }
        
        .email-container {
          max-width: 600px;
          margin: 0 auto;
          background: white;
          border-radius: 16px;
          overflow: hidden;
          box-shadow: 0 8px 30px rgba(0, 0, 0, 0.08);
        }
        
        .header {
          background: linear-gradient(135deg, ${SEEDS_BRANDING.primaryColor}, #1E40AF);
          padding: 30px;
          text-align: center;
        }
        
        .logo {
          max-width: 180px;
          height: auto;
          margin-bottom: 20px;
          display: block;
          margin-left: auto;
          margin-right: auto;
        }
        
        .header-title {
          color: white;
          font-size: 28px;
          font-weight: 600;
          margin-bottom: 10px;
          letter-spacing: 0.5px;
        }
        
        .header-subtitle {
          color: rgba(255, 255, 255, 0.9);
          font-size: 16px;
          letter-spacing: 0.3px;
        }
        
        .content {
          padding: 40px;
        }
        
        .alert-badge {
          background: ${SEEDS_BRANDING.secondaryColor};
          color: white;
          padding: 10px 25px;
          border-radius: 25px;
          display: inline-block;
          font-size: 14px;
          font-weight: 600;
          margin-bottom: 25px;
          letter-spacing: 0.5px;
        }
        
        /* Enhanced Table Styles */
        .details-table-container,
        .timeline-container {
          background: white;
          border-radius: 12px;
          padding: 25px;
          margin-bottom: 30px;
          border: 1px solid ${SEEDS_BRANDING.borderColor};
          box-shadow: 0 2px 8px rgba(0, 0, 0, 0.05);
        }
        
        .table-title {
          font-size: 18px;
          font-weight: 600;
          margin-bottom: 20px;
          color: ${SEEDS_BRANDING.textColor};
          display: flex;
          align-items: center;
          gap: 10px;
          border-bottom: 2px solid ${SEEDS_BRANDING.borderColor};
          padding-bottom: 10px;
        }
        
        .details-table {
          width: 100%;
          border-collapse: collapse;
          border-radius: 8px;
          overflow: hidden;
          box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
        }
        
        .details-table tbody tr {
          border-bottom: 1px solid ${SEEDS_BRANDING.borderColor};
          transition: background-color 0.2s;
        }
        
        .details-table tbody tr:hover {
          background-color: ${SEEDS_BRANDING.lightBg};
        }
        
        .details-table tbody tr:last-child {
          border-bottom: none;
        }
        
        .table-label {
          width: 35%;
          padding: 16px 20px;
          background: ${SEEDS_BRANDING.lightBg};
          font-weight: 600;
          color: ${SEEDS_BRANDING.textColor};
          font-size: 14px;
          text-transform: uppercase;
          letter-spacing: 0.5px;
          border-right: 2px solid white;
        }
        
        .table-value {
          padding: 16px 20px;
          color: #4A5568;
          font-size: 15px;
          font-weight: 500;
        }
        
        .table-value.highlight {
          color: ${SEEDS_BRANDING.primaryColor};
          font-weight: 600;
          font-size: 16px;
        }
        
        .table-value.email-cell {
          color: #4299E1;
          font-family: monospace;
          font-size: 14px;
        }
        
        .table-value.time-cell {
          color: #2D3748;
          font-weight: 500;
        }
        
        .table-value.purpose-cell {
          font-style: italic;
          color: #718096;
        }
        
        .table-value.id-cell {
          font-family: 'Courier New', monospace;
        }
        
        .badge {
          background: ${SEEDS_BRANDING.secondaryColor};
          color: white;
          padding: 4px 12px;
          border-radius: 20px;
          font-size: 12px;
          font-weight: 600;
          letter-spacing: 0.3px;
        }
        
        .status-badge {
          display: inline-block;
          padding: 6px 15px;
          border-radius: 20px;
          font-size: 12px;
          font-weight: 600;
          text-transform: uppercase;
          letter-spacing: 0.5px;
        }
        
        .status-badge.checked-in {
          background: linear-gradient(135deg, #48BB78, #38A169);
          color: white;
        }
        
        .status-badge.completed {
          background: linear-gradient(135deg, #48BB78, #38A169);
          color: white;
        }
        
        .status-badge.in-progress {
          background: linear-gradient(135deg, #ED8936, #DD6B20);
          color: white;
        }
        
        .status-badge.pending {
          background: linear-gradient(135deg, #A0AEC0, #718096);
          color: white;
        }
        
        /* Timeline Table */
        .timeline-table {
          width: 100%;
          border-collapse: separate;
          border-spacing: 0;
          border-radius: 8px;
          overflow: hidden;
          box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
        }
        
        .timeline-table thead {
          background: linear-gradient(135deg, ${SEEDS_BRANDING.primaryColor}, #1E40AF);
        }
        
        .timeline-table th {
          padding: 18px 20px;
          color: white;
          font-weight: 600;
          text-align: left;
          font-size: 14px;
          text-transform: uppercase;
          letter-spacing: 0.5px;
          border-right: 1px solid rgba(255, 255, 255, 0.1);
        }
        
        .timeline-table th:last-child {
          border-right: none;
        }
        
        .timeline-table td {
          padding: 16px 20px;
          color: #4A5568;
          font-size: 14px;
          font-weight: 500;
          border-bottom: 1px solid ${SEEDS_BRANDING.borderColor};
        }
        
        .timeline-table tbody tr:last-child td {
          border-bottom: none;
        }
        
        .timeline-table tbody tr:nth-child(even) {
          background-color: rgba(248, 249, 252, 0.5);
        }
        
        .timeline-table tbody tr:hover {
          background-color: ${SEEDS_BRANDING.lightBg};
          transform: scale(1.002);
          transition: all 0.2s ease;
        }
        
        .qr-section {
          text-align: center;
          padding: 30px;
          background: white;
          border-radius: 12px;
          border: 2px solid ${SEEDS_BRANDING.secondaryColor};
          margin-bottom: 30px;
          box-shadow: 0 4px 15px rgba(0, 212, 170, 0.1);
        }
        
        .qr-title {
          font-size: 20px;
          font-weight: 600;
          margin-bottom: 15px;
          color: ${SEEDS_BRANDING.textColor};
        }
        
        .qr-description {
          color: #64748B;
          margin-bottom: 25px;
          font-size: 15px;
          line-height: 1.6;
        }
        
        .qr-code {
          width: 220px;
          height: 220px;
          margin: 0 auto;
          border: 3px solid ${SEEDS_BRANDING.secondaryColor};
          border-radius: 12px;
          padding: 15px;
          background: white;
          display: flex;
          align-items: center;
          justify-content: center;
          box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
        }
        
        .qr-code img {
          width: 100%;
          height: 100%;
          object-fit: contain;
          border-radius: 6px;
        }
        
        .photo-section {
          text-align: center;
          padding: 30px;
          background: white;
          border-radius: 12px;
          border: 2px solid ${SEEDS_BRANDING.primaryColor};
          margin-bottom: 30px;
          box-shadow: 0 4px 15px rgba(46, 91, 255, 0.1);
        }
        
        .visitor-photo {
          width: 220px;
          height: 220px;
          object-fit: cover;
          border-radius: 12px;
          border: 3px solid ${SEEDS_BRANDING.primaryColor};
          box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
        }
        
        .instructions {
          background: linear-gradient(135deg, #F0F4FF, #E0E8FF);
          padding: 25px;
          border-radius: 12px;
          margin-bottom: 30px;
          border: 1px solid ${SEEDS_BRANDING.borderColor};
        }
        
        .instructions-title {
          font-size: 18px;
          font-weight: 600;
          margin-bottom: 15px;
          color: ${SEEDS_BRANDING.textColor};
          display: flex;
          align-items: center;
          gap: 10px;
        }
        
        .instructions-list {
          list-style: none;
          padding-left: 0;
        }
        
        .instructions-list li {
          margin-bottom: 12px;
          padding-left: 30px;
          position: relative;
          color: #4A5568;
          line-height: 1.6;
        }
        
        .instructions-list li:before {
          content: "✓";
          position: absolute;
          left: 0;
          color: ${SEEDS_BRANDING.secondaryColor};
          font-weight: bold;
          font-size: 16px;
          width: 22px;
          height: 22px;
          background: white;
          border-radius: 50%;
          display: flex;
          align-items: center;
          justify-content: center;
          border: 2px solid ${SEEDS_BRANDING.secondaryColor};
        }
        
        .footer {
          text-align: center;
          padding: 25px;
          background: ${SEEDS_BRANDING.lightBg};
          border-top: 1px solid ${SEEDS_BRANDING.borderColor};
          color: #64748B;
          font-size: 13px;
        }
        
        .footer-logo {
          max-width: 120px;
          margin-bottom: 15px;
          opacity: 0.8;
          display: block;
          margin-left: auto;
          margin-right: auto;
        }
        
        .footer-text {
          margin-bottom: 10px;
          line-height: 1.6;
        }
        
        .contact-info {
          font-size: 12px;
          color: #94A3B8;
          line-height: 1.6;
        }
        
        /* Responsive tables */
        @media (max-width: 600px) {
          .content {
            padding: 20px;
          }
          
          .details-table,
          .timeline-table {
            display: block;
            overflow-x: auto;
          }
          
          .header {
            padding: 20px;
          }
          
          .header-title {
            font-size: 24px;
          }
          
          .qr-code {
            width: 200px;
            height: 200px;
          }
          
          .table-label {
            width: 40%;
            padding: 12px 15px;
            font-size: 12px;
          }
          
          .table-value {
            padding: 12px 15px;
            font-size: 14px;
          }
          
          .timeline-table th,
          .timeline-table td {
            padding: 12px 15px;
            font-size: 12px;
          }
        }
      </style>
    </head>
    <body>
      <div class="email-container">
        <!-- Header with Logo -->
        <div class="header">
          <img src="${SEEDS_BRANDING.logoUrl}" alt="Seeds FinCap Logo" class="logo">
          <h1 class="header-title">Visitor Management System</h1>
          <p class="header-subtitle">Secure Digital Visitor Pass</p>
        </div>
        
        <!-- Main Content -->
        <div class="content">
          <!-- Alert Badge -->
          <div class="alert-badge">
            🛡️ NEW VISITOR ALERT
          </div>
          
          <!-- Visitor Details Table -->
          ${visitorTable}
          
          <!-- Timeline Table -->
          ${timelineTable}
          
          <!-- QR Code Section -->
          <div class="qr-section">
            <h3 class="qr-title">📱 Digital Visitor Pass</h3>
            <p class="qr-description">Scan this QR code to verify visitor details at security checkpoints</p>
            <div class="qr-code">
              <img src="cid:visitor-qr-code" alt="Visitor QR Code" width="200" height="200">
            </div>
            <div style="margin-top: 15px;">
              <table style="width: 100%; max-width: 300px; margin: 0 auto; border-collapse: collapse;">
                <tr>
                  <td style="text-align: center; padding: 8px; border: 1px solid ${SEEDS_BRANDING.borderColor};">
                    <small style="color: #64748B;">Visitor ID</small><br>
                    <strong>${visitorData.qr_id || visitorData.visitor_id || 'N/A'}</strong>
                  </td>
                  <td style="text-align: center; padding: 8px; border: 1px solid ${SEEDS_BRANDING.borderColor};">
                    <small style="color: #64748B;">Check-in Time</small><br>
                    <strong>${checkinTimeFormatted.timeOnly}</strong>
                  </td>
                </tr>
              </table>
            </div>
          </div>
          
          <!-- Visitor Photo Section (if available) -->
          ${hasPhoto ? `
            <div class="photo-section">
              <h3 class="qr-title">📸 Visitor Identification</h3>
              <p class="qr-description">Visitor photo for identification purposes</p>
              <img src="cid:visitor-photo" alt="Visitor Photo" class="visitor-photo">
            </div>
          ` : ''}
          
          <!-- Instructions -->
          <div class="instructions">
            <h3 class="instructions-title">
              <span style="font-size: 20px;">🔐</span> Security Instructions
            </h3>
            <table style="width: 100%; border-collapse: collapse; margin-top: 15px;">
              <tr>
                <td style="padding: 10px 15px; border: 1px solid ${SEEDS_BRANDING.borderColor}; width: 20%;">
                  <strong>1.</strong>
                </td>
                <td style="padding: 10px 15px; border: 1px solid ${SEEDS_BRANDING.borderColor};">
                  Meet visitor at reception within 15 minutes
                </td>
              </tr>
              <tr>
                <td style="padding: 10px 15px; border: 1px solid ${SEEDS_BRANDING.borderColor};">
                  <strong>2.</strong>
                </td>
                <td style="padding: 10px 15px; border: 1px solid ${SEEDS_BRANDING.borderColor};">
                  Keep QR code accessible for security verification
                </td>
              </tr>
              <tr>
                <td style="padding: 10px 15px; border: 1px solid ${SEEDS_BRANDING.borderColor};">
                  <strong>3.</strong>
                </td>
                <td style="padding: 10px 15px; border: 1px solid ${SEEDS_BRANDING.borderColor};">
                  Accompany visitor at all times within premises
                </td>
              </tr>
              <tr>
                <td style="padding: 10px 15px; border: 1px solid ${SEEDS_BRANDING.borderColor};">
                  <strong>4.</strong>
                </td>
                <td style="padding: 10px 15px; border: 1px solid ${SEEDS_BRANDING.borderColor};">
                  Ensure visitor checks out before leaving the building
                </td>
              </tr>
            </table>
          </div>
          
          <!-- Timezone Notice -->
          <div style="background: #F0F9FF; padding: 15px; border-radius: 8px; border-left: 4px solid #4299E1; margin-top: 20px;">
            <p style="color: #2D3748; margin: 0; font-size: 13px;">
              <strong>⏰ Time Zone Information:</strong><br>
              All times displayed are in <strong>Indian Standard Time (IST - GMT+5:30)</strong>. 
              Email sent at: ${currentTimeFormatted.timestamp}
            </p>
          </div>
        </div>
        
        <!-- Footer -->
        <div class="footer">
          <img src="${SEEDS_BRANDING.logoUrl}" alt="Seeds FinCap Logo" class="footer-logo">
          <table style="width: 100%; max-width: 500px; margin: 0 auto; border-collapse: collapse;">
            <tr>
              <td style="text-align: center; padding: 10px; border-bottom: 1px solid rgba(255,255,255,0.1);">
                <small style="color: #94A3B8;">Automated notification from Seeds FinCap Visitor Management System</small>
              </td>
            </tr>
            <tr>
              <td style="text-align: center; padding: 10px;">
                <strong style="color: white;">Seeds Fincap Pvt. Ltd.</strong><br>
                <small style="color: #94A3B8;">IT Support: itsupport@seedsfincap.com</small>
              </td>
            </tr>
          </table>
          <p style="margin-top: 15px; color: #94A3B8; font-size: 11px;">
            © ${new Date().getFullYear()} Seeds FinCap. All rights reserved.
          </p>
        </div>
      </div>
    </body>
    </html>
  `;
}

// Generate checkout email HTML template with beautiful tables
function generateCheckoutEmailHTML(visitorData, checkoutTime) {
  // Format times in IST (GMT+5:30)
  const checkoutTimeFormatted = formatDateTimeIST(checkoutTime);
  const checkinTimeFormatted = formatDateTimeIST(visitorData.checkin_time);
  const currentTimeFormatted = formatDateTimeIST(new Date());

  const formattedDuration = calculateVisitDuration(visitorData.checkin_time, checkoutTime);

  // Beautiful summary table
  const summaryTable = `
    <div class="summary-table-container">
      <h3 class="table-title">
        <span style="font-size: 20px;">📊</span> Visit Summary
      </h3>
      <table class="summary-table">
        <thead>
          <tr>
            <th colspan="2" style="background: linear-gradient(135deg, #10B981, #059669); color: white; text-align: center; padding: 15px;">
              Visitor Check-out Details
            </th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td class="summary-label">Visitor Name</td>
            <td class="summary-value highlight-name">${visitorData.visitor_name}</td>
          </tr>
          <tr>
            <td class="summary-label">Visit Duration</td>
            <td class="summary-value duration-cell">
              <span class="duration-badge">${formattedDuration}</span>
            </td>
          </tr>
          <tr>
            <td class="summary-label">Check-in Time</td>
            <td class="summary-value time-cell">
              <div style="display: flex; align-items: center; gap: 10px;">
                <span style="color: #4299E1;">⬇️</span>
                ${checkinTimeFormatted.fullDateTime}
              </div>
            </td>
          </tr>
          <tr>
            <td class="summary-label">Check-out Time</td>
            <td class="summary-value time-cell">
              <div style="display: flex; align-items: center; gap: 10px;">
                <span style="color: #48BB78;">⬆️</span>
                ${checkoutTimeFormatted.fullDateTime}
              </div>
            </td>
          </tr>
          <tr>
            <td class="summary-label">Host Employee</td>
            <td class="summary-value">${visitorData.host_employee || 'You'}</td>
          </tr>
          <tr>
            <td class="summary-label">Visit Status</td>
            <td class="summary-value">
              <span class="status-badge completed">✅ Completed</span>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  `;

  // Timeline table for checkout
  const checkoutTimeline = `
    <div class="timeline-container">
      <h3 class="table-title">
        <span style="font-size: 20px;">🔄</span> Visit Lifecycle
      </h3>
      <table class="checkout-timeline">
        <thead>
          <tr>
            <th style="width: 25%;">Phase</th>
            <th style="width: 25%;">Status</th>
            <th style="width: 25%;">Start Time (IST)</th>
            <th style="width: 25%;">End Time (IST)</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>Registration</td>
            <td><span class="phase-status completed">Completed</span></td>
            <td>${checkinTimeFormatted.timeOnly}</td>
            <td>${checkinTimeFormatted.timeOnly}</td>
          </tr>
          <tr>
            <td>Meeting</td>
            <td><span class="phase-status completed">Completed</span></td>
            <td>${checkinTimeFormatted.timeOnly}</td>
            <td>${checkoutTimeFormatted.timeOnly}</td>
          </tr>
          <tr>
            <td>Check-out</td>
            <td><span class="phase-status active">Just Completed</span></td>
            <td>${checkoutTimeFormatted.timeOnly}</td>
            <td>${checkoutTimeFormatted.timeOnly}</td>
          </tr>
        </tbody>
      </table>
    </div>
  `;

  return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Visitor Checked Out - Seeds FinCap</title>
      <style>
        * {
          margin: 0;
          padding: 0;
          box-sizing: border-box;
        }
        
        body {
          font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
          line-height: 1.6;
          color: ${SEEDS_BRANDING.textColor};
          background-color: #f5f7fa;
          -webkit-font-smoothing: antialiased;
          -moz-osx-font-smoothing: grayscale;
        }
        
        .email-container {
          max-width: 600px;
          margin: 0 auto;
          background: white;
          border-radius: 16px;
          overflow: hidden;
          box-shadow: 0 8px 30px rgba(0, 0, 0, 0.08);
        }
        
        .header {
          background: linear-gradient(135deg, #10B981, #059669);
          padding: 30px;
          text-align: center;
        }
        
        .logo {
          max-width: 180px;
          height: auto;
          margin-bottom: 20px;
          display: block;
          margin-left: auto;
          margin-right: auto;
        }
        
        .header-title {
          color: white;
          font-size: 28px;
          font-weight: 600;
          margin-bottom: 10px;
          letter-spacing: 0.5px;
        }
        
        .header-subtitle {
          color: rgba(255, 255, 255, 0.9);
          font-size: 16px;
          letter-spacing: 0.3px;
        }
        
        .content {
          padding: 40px;
        }
        
        .success-badge {
          background: #10B981;
          color: white;
          padding: 10px 25px;
          border-radius: 25px;
          display: inline-block;
          font-size: 14px;
          font-weight: 600;
          margin-bottom: 25px;
          letter-spacing: 0.5px;
        }
        
        /* Checkout-specific styles */
        .summary-table-container {
          background: white;
          border-radius: 12px;
          padding: 25px;
          margin-bottom: 30px;
          border: 1px solid #E0E6FF;
          box-shadow: 0 2px 8px rgba(0, 0, 0, 0.05);
        }
        
        .summary-table {
          width: 100%;
          border-collapse: collapse;
          border-radius: 8px;
          overflow: hidden;
          box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
        }
        
        .summary-label {
          width: 35%;
          padding: 16px 20px;
          background: #F8F9FC;
          font-weight: 600;
          color: #2E384D;
          font-size: 14px;
          text-transform: uppercase;
          letter-spacing: 0.5px;
          border-right: 2px solid white;
        }
        
        .summary-value {
          padding: 16px 20px;
          color: #4A5568;
          font-size: 15px;
          font-weight: 500;
        }
        
        .summary-value.highlight-name {
          color: #10B981;
          font-weight: 600;
          font-size: 16px;
        }
        
        .summary-value.duration-cell {
          text-align: center;
        }
        
        .summary-value.time-cell {
          font-family: monospace;
          font-size: 14px;
          font-weight: 600;
        }
        
        .duration-badge {
          background: linear-gradient(135deg, #10B981, #059669);
          color: white;
          padding: 8px 20px;
          border-radius: 25px;
          font-size: 14px;
          font-weight: 600;
          letter-spacing: 0.5px;
          display: inline-block;
          box-shadow: 0 2px 10px rgba(16, 185, 129, 0.2);
        }
        
        .checkout-timeline {
          width: 100%;
          border-collapse: separate;
          border-spacing: 0;
          border-radius: 8px;
          overflow: hidden;
          box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
        }
        
        .checkout-timeline thead {
          background: linear-gradient(135deg, #10B981, #059669);
        }
        
        .checkout-timeline th {
          padding: 18px 20px;
          color: white;
          font-weight: 600;
          text-align: left;
          font-size: 14px;
          text-transform: uppercase;
          letter-spacing: 0.5px;
          border-right: 1px solid rgba(255, 255, 255, 0.1);
        }
        
        .checkout-timeline th:last-child {
          border-right: none;
        }
        
        .checkout-timeline td {
          padding: 16px 20px;
          color: #4A5568;
          font-size: 14px;
          font-weight: 500;
          border-bottom: 1px solid #E0E6FF;
        }
        
        .checkout-timeline tbody tr:last-child td {
          border-bottom: none;
        }
        
        .checkout-timeline tbody tr:nth-child(even) {
          background-color: rgba(248, 249, 252, 0.5);
        }
        
        .phase-status {
          display: inline-block;
          padding: 6px 15px;
          border-radius: 20px;
          font-size: 12px;
          font-weight: 600;
          text-transform: uppercase;
          letter-spacing: 0.5px;
        }
        
        .phase-status.completed {
          background: linear-gradient(135deg, #48BB78, #38A169);
          color: white;
        }
        
        .phase-status.active {
          background: linear-gradient(135deg, #ED8936, #DD6B20);
          color: white;
          animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
          0% { opacity: 1; }
          50% { opacity: 0.8; }
          100% { opacity: 1; }
        }
        
        /* Add to your existing styles */
        .summary-table tbody tr {
          border-bottom: 1px solid #E0E6FF;
          transition: background-color 0.2s;
        }
        
        .summary-table tbody tr:hover {
          background-color: #F8F9FC;
        }
        
        .summary-table tbody tr:last-child {
          border-bottom: none;
        }
        
        .footer {
          text-align: center;
          padding: 25px;
          background: ${SEEDS_BRANDING.lightBg};
          border-top: 1px solid ${SEEDS_BRANDING.borderColor};
          color: #64748B;
          font-size: 13px;
        }
        
        .footer-logo {
          max-width: 120px;
          margin-bottom: 15px;
          opacity: 0.8;
          display: block;
          margin-left: auto;
          margin-right: auto;
        }
        
        @media (max-width: 600px) {
          .content {
            padding: 20px;
          }
          
          .summary-table,
          .checkout-timeline {
            display: block;
            overflow-x: auto;
          }
          
          .summary-label {
            width: 40%;
            padding: 12px 15px;
            font-size: 12px;
          }
          
          .summary-value {
            padding: 12px 15px;
            font-size: 14px;
          }
          
          .checkout-timeline th,
          .checkout-timeline td {
            padding: 12px 15px;
            font-size: 12px;
          }
        }
      </style>
    </head>
    <body>
      <div class="email-container">
        <div class="header">
          <img src="${SEEDS_BRANDING.logoUrl}" alt="Seeds FinCap Logo" class="logo">
          <h1 class="header-title">Visitor Check-out Complete</h1>
          <p class="header-subtitle">Security Notification</p>
        </div>
        
        <div class="content">
          <div class="success-badge">
            ✅ VISITOR CHECKED OUT SUCCESSFULLY
          </div>
          
          ${summaryTable}
          
          ${checkoutTimeline}
          
          <!-- Security Status Table -->
          <div style="background: #F0F9FF; padding: 25px; border-radius: 12px; margin-bottom: 30px; border: 2px solid #BEE3F8;">
            <table style="width: 100%; border-collapse: collapse;">
              <thead>
                <tr>
                  <th colspan="2" style="background: #4299E1; color: white; padding: 15px; text-align: center;">
                    🔒 Security Status Summary
                  </th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td style="padding: 15px; border: 1px solid #BEE3F8; font-weight: 600; width: 40%;">
                    Building Access
                  </td>
                  <td style="padding: 15px; border: 1px solid #BEE3F8; color: #059669;">
                    ✅ Revoked
                  </td>
                </tr>
                <tr>
                  <td style="padding: 15px; border: 1px solid #BEE3F8; font-weight: 600;">
                    Visitor Card
                  </td>
                  <td style="padding: 15px; border: 1px solid #BEE3F8; color: #059669;">
                    ✅ Returned
                  </td>
                </tr>
                <tr>
                  <td style="padding: 15px; border: 1px solid #BEE3F8; font-weight: 600;">
                    Visit Record
                  </td>
                  <td style="padding: 15px; border: 1px solid #BEE3F8; color: #059669;">
                    ✅ Archived
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          
          <!-- Timezone Notice -->
          <div style="background: #F0F9FF; padding: 15px; border-radius: 8px; border-left: 4px solid #4299E1; margin-top: 20px;">
            <p style="color: #2D3748; margin: 0; font-size: 13px;">
              <strong>⏰ Time Zone Information:</strong><br>
              All times displayed are in <strong>Indian Standard Time (IST - GMT+5:30)</strong>. 
              Email sent at: ${currentTimeFormatted.timestamp}
            </p>
          </div>
        </div>
        
        <div class="footer">
          <img src="${SEEDS_BRANDING.logoUrl}" alt="Seeds FinCap Logo" class="footer-logo">
          <p style="color: #64748B; font-size: 12px; margin-bottom: 10px; line-height: 1.6;">
            Automated notification from Seeds FinCap Visitor Management System
          </p>
          <p style="color: #94A3B8; font-size: 11px;">
            © ${new Date().getFullYear()} Seeds FinCap. All rights reserved.
          </p>
        </div>
      </div>
    </body>
    </html>
  `;
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
  // Skip health check for /api/health, /api/login and /api/visitors endpoints
  if (req.path === '/health' || req.path === '/login' || req.path === '/visitors') {
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

// Create Visitor (No authentication required for kiosk/reception)
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
    const qrId = `VIS-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    const qrData = {
      id: qrId,
      name: visitor_name,
      mobile: mobile || '',
      host: host_employee || '',
      purpose: purpose,
      checkin: new Date().toISOString(),
      status: 'checked_in'
    };

    // Generate QR code in multiple formats
    const qrCodeFormats = await generateQRCodeWithMultipleFormats(qrData);

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
    request.input('created_by', sql.NVarChar, 'public_kiosk');

    // Build dynamic INSERT query based on available columns
    let insertQuery = `
      INSERT INTO vs_visitors
        (visitor_name, mobile, host_employee, host_email, purpose, qr_code_data, created_by`;
    
    if (photo_base64) {
      insertQuery += `, photo_base64`;
    }
    
    insertQuery += `)
      OUTPUT INSERTED.id, INSERTED.checkin_time
      VALUES
        (@visitor_name, @mobile, @host_employee, @host_email, @purpose, @qr_code_data, @created_by`;
    
    if (photo_base64) {
      insertQuery += `, @photo_base64`;
    }
    
    insertQuery += `)`;

    const insertResult = await request.query(insertQuery);
    const visitorId = insertResult.recordset[0].id;
    const checkinTime = insertResult.recordset[0].checkin_time;

    // Prepare visitor data for email
    const visitorDataForEmail = {
      visitor_name,
      mobile,
      host_employee,
      host_email,
      purpose,
      checkin_time: checkinTime,
      qr_id: qrId,
      visitor_id: visitorId
    };

    // Send email notification with beautiful design and EMBEDDED QR CODE
    try {
      // Create email attachments array
      const attachments = [];
      
      // Add QR code as attachment with CID reference
      attachments.push({
        filename: `visitor-qr-${visitorId}.png`,
        content: qrCodeFormats.buffer,
        cid: 'visitor-qr-code', // This CID is referenced in the HTML
        contentType: 'image/png'
      });
      
      // Add photo if available
      if (photo_base64) {
        attachments.push({
          filename: `visitor-${visitorId}.jpg`,
          content: Buffer.from(photo_base64, 'base64'),
          cid: 'visitor-photo',
          contentType: 'image/jpeg'
        });
      }

      const mailOptions = {
        from: `"${process.env.EMAIL_FROM_NAME || 'Seeds FinCap Visitor System'}" <${EMAIL_CONFIG.auth.user}>`,
        to: host_email,
        subject: `🛡️ New Visitor: ${visitor_name} - Seeds FinCap`,
        html: generateVisitorEmailHTML(visitorDataForEmail, !!photo_base64),
        attachments: attachments
      };

      transporter.sendMail(mailOptions)
        .then(() => console.log(`✅ Beautiful email with EMBEDDED QR sent to ${host_email}`))
        .catch(err => {
          console.error('❌ Email send error:', err.message);
          console.error('❌ Email error details:', err);
        });
    } catch (emailErr) {
      console.error('Email generation error:', emailErr);
    }

    res.json({
      success: true,
      id: visitorId,
      qrCode: qrCodeFormats.dataURL,
      message: 'Visitor checked-in successfully!',
      visitor: {
        name: visitor_name,
        host: host_employee,
        checkinTime: checkinTime,
        visitorId: qrId
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

    // First get visitor details for email
    const getRequest = sqlPool.request();
    getRequest.input('id', sql.Int, visitorId);
    const visitorResult = await getRequest.query(`
      SELECT visitor_name, host_employee, host_email, checkin_time, status
      FROM vs_visitors
      WHERE id = @id
    `);

    if (!visitorResult.recordset.length) {
      return res.status(404).json({ 
        error: 'Visitor not found',
        code: 'VISITOR_NOT_FOUND'
      });
    }

    const visitor = visitorResult.recordset[0];
    
    if (visitor.status === 'checked_out') {
      return res.status(400).json({ 
        error: 'Visitor already checked out',
        code: 'ALREADY_CHECKED_OUT'
      });
    }

    // Perform checkout
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

    const checkoutTime = new Date();

    // Send checkout notification email if enabled
    if (visitor.host_email && process.env.SEND_CHECKOUT_EMAILS === 'true') {
      try {
        const mailOptions = {
          from: `"${process.env.EMAIL_FROM_NAME || 'Seeds FinCap Visitor System'}" <${EMAIL_CONFIG.auth.user}>`,
          to: visitor.host_email,
          subject: `✅ Visitor Check-out: ${visitor.visitor_name} - Seeds FinCap`,
          html: generateCheckoutEmailHTML(visitor, checkoutTime)
        };
        
        transporter.sendMail(mailOptions)
          .then(() => console.log(`✅ Checkout email sent to ${visitor.host_email}`))
          .catch(err => console.error('❌ Checkout email error:', err.message));
      } catch (emailErr) {
        console.error('Checkout email generation error:', emailErr.message);
      }
    }

    res.json({ 
      success: true,
      message: 'Visitor checked out successfully',
      checkoutTime: checkoutTime.toISOString(),
      visitor: {
        id: visitorId,
        name: visitor.visitor_name,
        host: visitor.host_employee
      }
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
✅ Timezone: GMT+5:30 (Indian Standard Time)
✅ QR Code Fix: EMBEDDED as email attachment
✅ Beautiful Email Templates: ✓
✅ Public Visitor Creation: No authentication required
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