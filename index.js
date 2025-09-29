require('dotenv').config();

const express = require('express');
const { Pool } = require('pg'); // Changed from mssql to pg
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const puppeteer = require('puppeteer');
const handlebars = require('handlebars');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const authRoutes = require('./routes/auth');
const { authenticateToken, requireCompanyAccess } = require('./middleware/auth');
const multer = require('multer');
const app = express();

// Status mapping functions for booking system
function mapStatusToInt(statusString) {
  const statusMap = {
    'Pending': 1,
    'Confirmed': 2,
    'In Transit': 3,
    'Delivered': 4,
    'Cancelled': 5
  };
  
  if (typeof statusString === 'number') return statusString;
  if (typeof statusString === 'string') return statusMap[statusString] || 1;
  return 1;
}

function mapStatusToString(statusInt) {
  const statusMap = {
    1: 'Pending',
    2: 'Confirmed', 
    3: 'In Transit',
    4: 'Delivered',
    5: 'Cancelled'
  };
  return statusMap[statusInt] || 'Pending';
}

const port = 3000;

// Digital signature secret key for VPL security
const VPL_SECRET_KEY = process.env.VPL_SECRET_KEY || 'your-super-secret-vpl-key-change-this-in-production';

// Universal date handler to fix dayjs corruption issues
function sanitizeDate(dateValue) {
  if (!dateValue) return null;
  
  try {
    let cleanDate;
    
    // Handle dayjs object
    if (dateValue.format) {
      cleanDate = new Date(dateValue.format('YYYY-MM-DD'));
    }
    // Handle moment object
    else if (dateValue._isAMomentObject) {
      cleanDate = dateValue.toDate();
    }
    // Handle clean YYYY-MM-DD string from frontend
    else if (typeof dateValue === 'string' && dateValue.match(/^\d{4}-\d{2}-\d{2}$/)) {
      // Force UTC parsing to prevent timezone corruption
      cleanDate = new Date(dateValue + 'T00:00:00.000Z');
    }
    // Handle ISO string or other date formats
    else {
      cleanDate = new Date(dateValue);
    }
    
    // Validate date range (reasonable range for PostgreSQL)
    if (isNaN(cleanDate.getTime()) || 
        cleanDate.getFullYear() < 1900 || 
        cleanDate.getFullYear() > 2100) {
      console.warn('Invalid date detected, returning null:', dateValue);
      return null;
    }
    
    return cleanDate;
  } catch (error) {
    console.warn('Date sanitization failed, returning null:', error);
    return null;
  }
}

// Digital signature functions for Virtual Packing Lists
const generateSecurityHash = (packingListData) => {
  try {
    // Remove any existing hash to avoid circular reference
    const cleanData = { ...packingListData };
    delete cleanData.securityHash;
    
    // Create deterministic string from data (sorted keys for consistency)
    const dataString = JSON.stringify(cleanData, Object.keys(cleanData).sort());
    
    // Generate HMAC-SHA256 hash
    const hash = crypto.createHmac('sha256', VPL_SECRET_KEY)
                      .update(dataString)
                      .digest('hex');
    
    console.log('Generated security hash for VPL');
    return hash;
  } catch (error) {
    console.error('Error generating security hash:', error);
    throw error;
  }
};

const verifySecurityHash = (packingListData) => {
  try {
    const uploadedHash = packingListData.securityHash;
    const calculatedHash = generateSecurityHash(packingListData);
    
    const isValid = uploadedHash === calculatedHash;
    
    console.log('VPL Security Verification:', {
      isValid,
      uploadedHash: uploadedHash?.substring(0, 8) + '...',
      calculatedHash: calculatedHash?.substring(0, 8) + '...'
    });
    
    return {
      isValid,
      uploadedHash,
      calculatedHash
    };
  } catch (error) {
    console.error('Error verifying security hash:', error);
    return {
      isValid: false,
      error: error.message
    };
  }
};

/**
 * Complete PostgreSQL Data Cleanup Middleware
  */
const cleanPostgreSQLData = (req, res, next) => {
  console.log('🚨 MIDDLEWARE RUNNING - URL:', req.url, 'METHOD:', req.method);
  if (req.body && typeof req.body === 'object') {
    console.log('🧹 Cleaning data for PostgreSQL...');
    const cleanedBody = { ...req.body };
    
    // COMPLETE LIST: All integer, numeric, bigint, smallint fields from your schema
    const NUMERIC_FIELDS = [
      // clients table
      'client_id',
      
      // collectionitems table
      'collectedquantity', 'collectionid', 'expectedquantity', 'itemid',
      
      // communications table
      'communicationid', 'orderid', 'userid',
      
      // companies table
      'companyid',
      
      // documents table
      'documentid', 'filesize', 'orderid', 'uploadedbyuserid',
      
      // finalinvoice table
      'finalinvoiceid', 'orderid', 'shippingcost', 'subtotal', 'taxamount', 
      'taxrate', 'totalamount',
      
      // groupproducts table
      'groupid', 'productid',
      
      // invoices table
      'orderid',
      
      // loadcalculator table
      'loadid', 'orderid', 'volume', 'weight',
      
      // milestones table
      'completedbyuserid', 'milestoneid', 'orderid', 'userid',
      
      // orderdetails table
      'orderdetailid', 'orderid',
      
      // orderlines table
      'lineid', 'linenumber', 'orderid', 'poinvoiceid', 'productid', 
      'quantity', 'unitprice', 'volume', 'weight',
      
      // orders table
      'orderid', 'actualvolumemeasure', 'actualweightmeasure', 'packs', 'userid',
      
      // permissions table
      'permissionid',
      
      // planning table
      'orderid', 'packs', 'planningid',
      
      // pobooking table
      'pobookingid', 'status',
      
      // pobookinglink table
      'bookedqty', 'orderid', 'pobookingid', 'pobookinglinkid',
      
      // pobookinglinks table
      'bookedqty', 'pobookingid', 'pobookinglinkid', 'purchaseorderid',
      
      // pobookings table
      'pobookingid', 'status',
      
      // poinvoice table (your main invoice table)
      'containercount', 'foreignvalue', 'grossweight', 'netweight', 
      'orderid', 'packagecount', 'poinvoiceid', 'randamount', 'roe', 
      'taxamount', 'transactiontype', 'vendorid', 'volume',
      
      // poinvoices table (duplicate table?)
      'containercount', 'foreignvalue', 'grossweight', 'netweight', 
      'orderid', 'packagecount', 'poinvoiceid', 'randamount', 'roe', 
      'taxamount', 'transactiontype', 'vendorid', 'volume',
      
      // productgroups table
      'groupid', 'userid',
      
      // products table
      'productid', 'stock', 'unitprice', 'volume', 'weight',
      
      // reporthistory table
      'id', 'reportid', 'userid',
      
      // reports table
      'id', 'userid',
      
      // savedimports table
      'id', 'totalrows', 'userid',
      
      // stockcollections table
      'collectionid',
      
      // suppliers table
      'supplier_id',
      
      // tracking table
      'orderid', 'trackingid',
      
      // tradingpartners table
      'exportercompanyid', 'importercompanyid', 'partnershipid',
      
      // transportation table
      'orderid', 'transportationid',
      
      // usercompanyroles table
      'companyid', 'usercompanyroleid', 'userid',
      
      // userpermissions table
      'companyid', 'grantedby', 'permissionid', 'userid', 'userpermissionid',
      
      // userpreferences table
      'id', 'userid',
      
      // users table
      'userid',
      
      // virtualpackinglistreferences table
      'exportorderid', 'importorderid', 'referenceid', 'totallines', 
      'totalquantity', 'totalvalue',
      
      // virtualshelves table
      'id'
    ];
    
    // Clean numeric fields - convert empty strings/undefined to null
    NUMERIC_FIELDS.forEach(field => {
      if (cleanedBody.hasOwnProperty(field)) {
        const value = cleanedBody[field];
        
        if (value === '' || value === 'undefined' || value === undefined || value === 'null') {
          cleanedBody[field] = null;
          console.log(`🔧 ${field}: "${value}" → null`);
        }
        // Convert valid numeric strings to numbers
        else if (typeof value === 'string' && !isNaN(value) && value.trim() !== '') {
          const numValue = value.includes('.') ? parseFloat(value) : parseInt(value);
          cleanedBody[field] = numValue;
          console.log(`🔧 ${field}: "${value}" → ${numValue}`);
        }
      }
    });
    
    // Clean string fields that might be undefined
    Object.keys(cleanedBody).forEach(key => {
      if (!NUMERIC_FIELDS.includes(key)) {
        if (cleanedBody[key] === undefined || cleanedBody[key] === 'undefined') {
          cleanedBody[key] = '';
          console.log(`🔧 String field ${key}: undefined → ""`);
        }
      }
    });
    
    req.body = cleanedBody;
    console.log('✅ Data cleaning complete');
  }
  
  next();
};

// Middleware
app.use(bodyParser.json());
app.use(cors());
app.use(cleanPostgreSQLData);


// Serve static files from the public folder so that the logo is accessible
app.use(express.static(path.join(__dirname, 'public')));

// Authentication routes
app.use('/api/auth', authRoutes);

// --- Test Endpoint for Debugging ---
app.post('/test', (req, res) => {
  console.log("POST /test endpoint hit!");
  res.json({ message: "Test endpoint working!" });
});

// PostgreSQL Configuration - CONVERTED FROM SQL SERVER
const dbConfig = {
  user: process.env.DB_USER || 'postgres',
  host: process.env.DB_HOST || 'localhost',
  database: process.env.DB_NAME || 'postgres',
  password: process.env.DB_PASSWORD || 'Bluemoon312',
  port: process.env.DB_PORT || 5432,
  // PostgreSQL connection pool settings
  max: 20, // Maximum number of clients in the pool
  idleTimeoutMillis: 30000, // How long a client is allowed to remain idle
  connectionTimeoutMillis: 2000, // How long to wait for a connection
};

// Create PostgreSQL connection pool
const pool = new Pool(dbConfig);


// Connect to PostgreSQL with improved error handling - CONVERTED
async function connectDB() {
  try {
    const client = await pool.connect();
    console.log("Connected to PostgreSQL!");
    
    // Test the connection with a simple query
    const result = await client.query('SELECT version()');
    console.log("Database version:", result.rows[0].version);
    
    // IMPORTANT: Set up the database pool for auth middleware
    app.locals.dbPool = pool;
    
    // Verify if authentication tables exist and have the correct column names
    try {
      const tableCheckResult = await client.query(`
        SELECT table_name
        FROM information_schema.tables 
        WHERE table_schema = 'public' AND table_name IN ('users', 'companies', 'usercompanyroles')
      `);
      
      const existingTables = tableCheckResult.rows.map(r => r.table_name);
      console.log("Authentication tables found:", existingTables);
      
      // Check for the case-sensitive Role column
      if (existingTables.includes('usercompanyroles')) {
        const columnCheckResult = await client.query(`
          SELECT column_name 
          FROM information_schema.columns 
          WHERE table_name = 'usercompanyroles' AND column_name = 'Role'
        `);
        
        if (columnCheckResult.rows.length > 0) {
          console.log("Warning: usercompanyroles.Role column found - requires quotes in queries.");
        }
      }
    } catch (tableCheckErr) {
      console.log("Authentication tables check completed.");
    }
    
    client.release();
    return pool;
  } catch (err) {
    console.error("Database connection failed:", err);
    return false;
  }
}

// Check if OrderLines table exists and create if not - CONVERTED
async function ensureOrderLinesTable() {
  try {
    // First check if Orders table exists
    const ordersTableCheck = await pool.query(`
      SELECT COUNT(*) as count FROM information_schema.tables 
      WHERE table_schema = 'public' AND table_name = 'orders'
    `);
    
    const ordersTableExists = parseInt(ordersTableCheck.rows[0].count) > 0;
    
    // Check if OrderLines table exists
    const orderLinesTableCheck = await pool.query(`
      SELECT COUNT(*) as count FROM information_schema.tables 
      WHERE table_schema = 'public' AND table_name = 'orderlines'
    `);
    
    if (parseInt(orderLinesTableCheck.rows[0].count) === 0) {
      console.log("Creating OrderLines table...");
      
      // If Orders table exists, create with foreign key constraint
      if (ordersTableExists) {
        await pool.query(`
          CREATE TABLE orderlines (
            lineid SERIAL PRIMARY KEY,
            orderid INT NOT NULL,
            poinvoiceid INT NULL,
            ordernumber VARCHAR(255),
            linenumber INT,
            partnumber VARCHAR(255),
            description TEXT,
            quantity INT,
            uom VARCHAR(50),
            linestatus VARCHAR(50),
            productid INT,
            unitprice DECIMAL(10,2),
            weight DECIMAL(10,2),
            volume DECIMAL(10,2),
            createdat TIMESTAMP DEFAULT NOW(),
            updatedat TIMESTAMP DEFAULT NOW(),
            CONSTRAINT fk_orderlines_order FOREIGN KEY (orderid) REFERENCES orders(orderid) ON DELETE CASCADE
          )
        `);
      } else {
        // Create without foreign key if Orders table doesn't exist
        await pool.query(`
          CREATE TABLE orderlines (
            lineid SERIAL PRIMARY KEY,
            orderid INT NOT NULL,
            poinvoiceid INT NULL,
            ordernumber VARCHAR(255),
            linenumber INT,
            partnumber VARCHAR(255),
            description TEXT,
            quantity INT,
            uom VARCHAR(50),
            linestatus VARCHAR(50),
            productid INT,
            unitprice DECIMAL(10,2),
            weight DECIMAL(10,2),
            volume DECIMAL(10,2),
            createdat TIMESTAMP DEFAULT NOW(),
            updatedat TIMESTAMP DEFAULT NOW()
          )
        `);
        console.warn("Warning: Created OrderLines table without foreign key constraint because Orders table does not exist.");
      }
      
      console.log("OrderLines table created successfully!");
    } else {
      console.log("OrderLines table already exists, checking columns...");
      
      // Check if POInvoiceID column exists
      const columnCheck = await pool.query(`
        SELECT COUNT(*) as count 
        FROM information_schema.columns 
        WHERE table_schema = 'public' AND table_name = 'orderlines' AND column_name = 'poinvoiceid'
      `);
      
      if (parseInt(columnCheck.rows[0].count) === 0) {
        console.log("Adding poinvoiceid column to existing OrderLines table...");
        await pool.query(`
          ALTER TABLE orderlines 
          ADD COLUMN poinvoiceid INT NULL
        `);
        console.log("poinvoiceid column added successfully!");
      } else {
        console.log("poinvoiceid column already exists.");
      }
      
      // Check for other missing columns
      const columnsToCheck = ['unitprice', 'weight', 'volume'];
      for (const column of columnsToCheck) {
        const colCheck = await pool.query(`
          SELECT COUNT(*) as count 
          FROM information_schema.columns 
          WHERE table_schema = 'public' AND table_name = 'orderlines' AND column_name = $1
        `, [column]);
        
        if (parseInt(colCheck.rows[0].count) === 0) {
          console.log(`Adding ${column} column to OrderLines table...`);
          await pool.query(`
            ALTER TABLE orderlines 
            ADD COLUMN ${column} DECIMAL(10,2) NULL
          `);
          console.log(`${column} column added successfully!`);
        }
      }
    }
  } catch (err) {
    console.error("Error checking/creating OrderLines table:", err);
  }
}

async function ensureProductsTable() {
  try {
    // Check if Products table exists
    const tableCheck = await pool.query(`
      SELECT COUNT(*) as count FROM information_schema.tables 
      WHERE table_schema = 'public' AND table_name = 'products'
    `);
    
    if (parseInt(tableCheck.rows[0].count) === 0) {
      console.log("Creating Products table...");
      await pool.query(`
        CREATE TABLE products (
          productid SERIAL PRIMARY KEY,
          name VARCHAR(255) NOT NULL,
          sku VARCHAR(100),
          category VARCHAR(100),
          stock INT,
          description TEXT,
          unitprice DECIMAL(10,2),
          weight DECIMAL(10,2),
          volume DECIMAL(10,2),
          sellbydate DATE,
          createdat TIMESTAMP DEFAULT NOW(),
          updatedat TIMESTAMP DEFAULT NOW()
        )
      `);
      console.log("Products table created successfully!");
    } else {
      console.log("Products table already exists.");
      
      // Check for missing columns and add them
      const columnsToCheck = [
        { name: 'unitprice', type: 'DECIMAL(10,2)' },
        { name: 'weight', type: 'DECIMAL(10,2)' },
        { name: 'volume', type: 'DECIMAL(10,2)' },
        { name: 'sellbydate', type: 'DATE' }
      ];

      for (const column of columnsToCheck) {
        const colCheck = await pool.query(`
          SELECT COUNT(*) as count 
          FROM information_schema.columns 
          WHERE table_schema = 'public' AND table_name = 'products' AND column_name = $1
        `, [column.name]);

        if (parseInt(colCheck.rows[0].count) === 0) {
          console.log(`Adding ${column.name} column...`);
          await pool.query(`ALTER TABLE products ADD COLUMN ${column.name} ${column.type}`);
          console.log(`${column.name} column added successfully!`);
        } else {
          console.log(`${column.name} column already exists.`);
        }
      }
    }
  } catch (err) {
    console.error("Error checking/creating Products table:", err);
  }
}

// Email Notification Setup using MailDev
const transporter = nodemailer.createTransport({
  host: 'localhost',    // MailDev host
  port: 1025,           // MailDev SMTP port
  ignoreTLS: true       // No TLS needed for local dev
});

// POST /notify - Send a notification email using MailDev
app.post('/notify', async (req, res) => {
  console.log("POST /notify endpoint hit!");
  const { orderNumber, status, exporterEmail, consigneeEmail, message } = req.body;
  
  if (!orderNumber || !status || !exporterEmail || !consigneeEmail || !message) {
    return res.status(400).json({ error: "Missing required notification fields" });
  }
  
  const mailOptions = {
    from: 'no-reply@example.com',
    to: [exporterEmail, consigneeEmail].join(","),
    subject: `Notification: Purchase Order ${orderNumber} Update`,
    text: message,
  };

  transporter.sendMail(mailOptions, (err, info) => {
    if (err) {
      console.error("Error sending notification email:", err);
      return res.status(500).json({ error: "Failed to send notification email" });
    }
    console.log("Notification email sent:", info.response);
    res.status(200).json({ message: "Notification email sent successfully", info });
  });
});

/* ---------------------------------------------------------------
   Invoice Generation Helper Function
   - Reads the HTML template from "templates/invoiceTemplate.html"
   - Compiles it using Handlebars with provided invoiceData
   - Uses Puppeteer to render the HTML into a PDF buffer
---------------------------------------------------------------- */
async function generateInvoicePDF(invoiceData) {
  try {
    const templatePath = path.join(__dirname, 'templates', 'invoiceTemplate.html');
    const templateContent = fs.readFileSync(templatePath, 'utf8');

    // Compile the template
    const template = handlebars.compile(templateContent);
    const html = template(invoiceData);

    // Launch Puppeteer
    const browser = await puppeteer.launch({
    executablePath: process.env.NODE_ENV === 'production' ? '/usr/bin/google-chrome-stable' : undefined,
    headless: true,
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-dev-shm-usage',
      '--disable-gpu',
      '--single-process'
    ]
  });
    const page = await browser.newPage();
    await page.setContent(html, { waitUntil: 'networkidle0' });
    // Generate PDF in A4 format
    const pdfBuffer = await page.pdf({ format: 'A4' });
    await browser.close();

    return pdfBuffer;
  } catch (err) {
    console.error("Error in generateInvoicePDF:", err);
    throw err;
  }
}

/* ---------------------------------------------------------------
   Orders Routes - CONVERTED TO POSTGRESQL
--------------------------------------------------------------- */

// GET all orders - CONVERTED
app.get('/orders', async (req, res) => {
  console.log("GET /orders called.");
  try {
    const result = await pool.query('SELECT * FROM orders ORDER BY orderid DESC');
    console.log("Records returned from /orders:", result.rows.length);
    res.status(200).json(result.rows);
  } catch (err) {
    console.error("Error fetching orders:", err);
    res.status(500).json({ error: err.message });
  }
});

// POST - Create a new order including userID - CONVERTED
app.post('/orders', async (req, res) => {
  console.log("POST /orders called. Incoming body:", req.body);
  const {
    userid,
    orderstatus,
    ordernumber,
    splitnumber,
    goodsdescription,
    orderdate,
    exporter,
    shipmentconsignee,
    exportercontact,
    shipmentconsigneecontact,
    confirmationdate,
    followupdate,
    exworksrequiredby,
    requiredinstore,
    shipwindowstart,
    shipwindowend,
    apn,
    currency,
    packs,
    packtype,
    actualweightmeasure,
    actualvolumemeasure,
    additionaldetails,
    invoicenumber,
    invoicedate,
    transportmode,
    destination,
    origin,
    portofdischarge,
    portofloading,
    servicelevel,
    containermode,
    incoterm
  } = req.body;
  
  try {
    const query = `
      INSERT INTO orders (
        userid, orderstatus, ordernumber, splitnumber, goodsdescription, orderdate,
        exporter, shipmentconsignee, exportercontact, shipmentconsigneecontact,
        confirmationdate, followupdate, exworksrequiredby, requiredinstore,
        shipwindowstart, shipwindowend, apn, currency, packs, packtype, actualweightmeasure,
        actualvolumemeasure, additionaldetails, invoicenumber, invoicedate,
        transportmode, destination, origin, portofdischarge, portofloading,
        servicelevel, containermode, incoterm
      )
      VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, 
        $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33
      ) RETURNING orderid
    `;

    const result = await pool.query(query, [
      userid, orderstatus, ordernumber, splitnumber, goodsdescription, sanitizeDate(orderdate),
      exporter, shipmentconsignee, exportercontact, shipmentconsigneecontact,
      sanitizeDate(confirmationdate), sanitizeDate(followupdate), sanitizeDate(exworksrequiredby), 
      sanitizeDate(requiredinstore), sanitizeDate(shipwindowstart), sanitizeDate(shipwindowend), 
      apn, currency, packs, packtype, actualweightmeasure, actualvolumemeasure, additionaldetails, 
      invoicenumber, sanitizeDate(invoicedate), transportmode, destination, origin, portofdischarge, 
      portofloading, servicelevel, containermode, incoterm
    ]);

    console.log("Order created successfully!");
    
    // Get the inserted ID
    const orderid = result.rows[0].orderid;
    
    res.status(201).json({ message: 'Order created successfully', orderid: orderid });
  } catch (err) {
    console.error("Order creation failed:", err);
    res.status(500).json({ error: err.message });
  }
});

// GET a single order by ID - CONVERTED
app.get('/orders/:id', async (req, res) => {
  console.log("GET /orders/:id called, ID =", req.params.id);
  const { id } = req.params;

 // Add validation for undefined/invalid IDs
  if (!id || id === 'undefined' || isNaN(parseInt(id))) {
    console.log("Invalid order ID provided:", id);
    return res.status(400).json({ error: 'Invalid order ID provided' });
  }
  
  try {
    const query = `SELECT * FROM orders WHERE orderid = $1`;
    const result = await pool.query(query, [id]);

    if (result.rows.length === 0) {
      console.log("No order found with ID =", id);
      return res.status(404).json({ message: 'Order not found' });
    }

    console.log("Record returned:", result.rows[0]);
    res.status(200).json(result.rows[0]);
  } catch (err) {
    console.error("Error fetching order:", err);
    res.status(500).json({ error: err.message });
  }
});

// PUT - Update an order - CONVERTED
app.put('/orders/:id', async (req, res) => {
  console.log("PUT /orders/:id called, ID =", req.params.id);
  console.log("Incoming PUT body:", req.body);
  const { id } = req.params;
  const {
    userid,
    orderstatus,
    ordernumber,
    splitnumber,
    goodsdescription,
    orderdate,
    exporter,
    shipmentconsignee,
    exportercontact,
    shipmentconsigneecontact,
    confirmationdate,
    followupdate,
    exworksrequiredby,
    requiredinstore,
    shipwindowstart,
    shipwindowend,
    apn,
    currency,
    packs,
    packtype,
    actualweightmeasure,
    actualvolumemeasure,
    additionaldetails,
    invoicenumber,
    invoicedate,
    transportmode,
    destination,
    origin,
    portofdischarge,
    portofloading,
    servicelevel,
    containermode,
    incoterm,
    ordertype
  } = req.body;

  console.log('Raw values before cleaning:', { packs, actualweightmeasure, actualvolumemeasure });

// Clean numeric fields that might be empty strings
const cleanedPacks = (packs === '' || packs === undefined || packs === null) ? null : parseInt(packs) || null;
const cleanedActualWeightMeasure = (actualweightmeasure === '' || actualweightmeasure === undefined || actualweightmeasure === null) ? null : parseFloat(actualweightmeasure) || null;
const cleanedActualVolumeMeasure = (actualvolumemeasure === '' || actualvolumemeasure === undefined || actualvolumemeasure === null) ? null : parseFloat(actualvolumemeasure) || null;

console.log('Cleaned values:', { 
  cleanedPacks, 
  cleanedActualWeightMeasure, 
  cleanedActualVolumeMeasure 
});

try {
    const query = `
      UPDATE orders
      SET
        userid = $2,
        orderstatus = $3,
        ordernumber = $4,
        splitnumber = $5,
        goodsdescription = $6,
        orderdate = $7,
        exporter = $8,
        shipmentconsignee = $9,
        exportercontact = $10,
        shipmentconsigneecontact = $11,
        confirmationdate = $12,
        followupdate = $13,
        exworksrequiredby = $14,
        requiredinstore = $15,
        shipwindowstart = $16,
        shipwindowend = $17,
        apn = $18,
        currency = $19,
        packs = $20,
        packtype = $21,
        actualweightmeasure = $22,
        actualvolumemeasure = $23,
        additionaldetails = $24,
        invoicenumber = $25,
        invoicedate = $26,
        transportmode = $27,
        destination = $28,
        origin = $29,
        portofdischarge = $30,
        portofloading = $31,
        servicelevel = $32,
        containermode = $33,
        incoterm = $34,
        ordertype = $35
      WHERE orderid = $1
    `;

    await pool.query(query, [
      id, userid, orderstatus, ordernumber, splitnumber, goodsdescription, sanitizeDate(orderdate),
      exporter, shipmentconsignee, exportercontact, shipmentconsigneecontact,
      sanitizeDate(confirmationdate), sanitizeDate(followupdate), sanitizeDate(exworksrequiredby), 
      sanitizeDate(requiredinstore), sanitizeDate(shipwindowstart), sanitizeDate(shipwindowend), 
      apn, currency, cleanedPacks, packtype, cleanedActualWeightMeasure, cleanedActualVolumeMeasure, additionaldetails, 
      invoicenumber, sanitizeDate(invoicedate), transportmode, destination, origin, portofdischarge, 
      portofloading, servicelevel, containermode, incoterm, ordertype || 'Export'
    ]);

    console.log("Order updated successfully!");
    res.status(200).json({ message: 'Order updated successfully' });
  } catch (err) {
    console.error("Order update failed:", err);
    res.status(500).json({ error: err.message });
  }
});

// DELETE - Delete an order - CONVERTED
app.delete('/orders/:id', async (req, res) => {
  console.log("DELETE /orders/:id called, ID =", req.params.id);
  const { id } = req.params;
  try {
    const query = `DELETE FROM orders WHERE orderid = $1`;
    await pool.query(query, [id]);
    console.log("Order deleted successfully!");
    res.status(200).json({ message: 'Order deleted successfully' });
  } catch (err) {
    console.error("Order deletion failed:", err);
    res.status(500).json({ error: err.message });
  }
});

// GET orders for authenticated user - CONVERTED
app.get('/api/orders', authenticateToken, async (req, res) => {
  console.log("GET /api/orders called for authenticated user:", req.user.userId);
  try {
    // Get user's company IDs from the authenticated token
    const userCompanyIds = req.user.companies.map(c => c.companyId);
    
    if (userCompanyIds.length === 0) {
      return res.status(200).json([]);
    }
    
    const query = `SELECT * FROM orders WHERE userid = $1 ORDER BY orderid DESC`;
    const result = await pool.query(query, [req.user.userId]);

    console.log(`${result.rows.length} orders found for user ${req.user.userId}`);
    res.status(200).json(result.rows);
  } catch (err) {
    console.error("Error fetching user orders:", err);
    res.status(500).json({ error: err.message });
  }
});

/* ---------------------------------------------------------------
   NEW: ORDER LINES ENDPOINTS - POSTGRESQL VERSION
---------------------------------------------------------------- */

app.get('/orderLines', async (req, res) => {
  console.log("GET /orderLines called with query:", req.query);
  try {
    // First check if the table exists
    const tableCheck = await pool.query(`
      SELECT COUNT(*) as count FROM information_schema.tables 
      WHERE table_schema = 'public' AND table_name = 'orderlines'
    `);
    
    if (parseInt(tableCheck.rows[0].count) === 0) {
      console.log("OrderLines table does not exist yet.");
      return res.status(200).json([]);
    }
    
    let query = `
      SELECT 
        ol.*,
        p.weight,
        p.volume,
        p.unitprice as productunitprice
      FROM orderlines ol 
      LEFT JOIN products p ON ol.productid = p.productid
    `;
    
    let params = [];
    
    // Support filtering by POInvoiceID
    if (req.query.poinvoiceid) {
      query += ' WHERE ol.poinvoiceid = $1';
      params.push(req.query.poinvoiceid);
      console.log(`Filtering by poinvoiceid: ${req.query.poinvoiceid}`);
    }
    // Filter by OrderID if provided (legacy support)
    else if (req.query.orderid) {
      query += ' WHERE ol.orderid = $1';
      params.push(req.query.orderid);
      console.log(`Filtering by orderid: ${req.query.orderid}`);
    }
    
    query += ' ORDER BY ol.lineid';
    const result = await pool.query(query, params);
    console.log("Records returned from /orderLines:", result.rows.length);
    res.status(200).json(result.rows);
  } catch (err) {
    console.error("Error fetching order lines:", err);
    res.status(200).json([]);
  }
});

// POST /orderLines endpoint - CONVERTED
app.post('/orderLines', async (req, res) => {
  console.log("POST /orderLines called. Incoming body:", req.body);
  const {
    orderid,
    poinvoiceid,
    ordernumber,
    linenumber,
    partnumber,
    description,
    quantity,
    uom,
    linestatus,
    productid,
    unitprice,
    weight,
    volume
  } = req.body;
  
  try {
    // Check if the table exists first
    await ensureOrderLinesTable();
    
    const query = `
      INSERT INTO orderlines (
        orderid, poinvoiceid, ordernumber, linenumber, partnumber, description, 
        quantity, uom, linestatus, productid, unitprice, weight, volume, createdat, updatedat
      )
      VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW(), NOW()
      )
      RETURNING lineid
    `;

    const result = await pool.query(query, [
      orderid, poinvoiceid || null, ordernumber, linenumber || 0, partnumber,
      description, quantity, uom || 'UNIT', linestatus || 'Pending', productid,
      unitprice || 0, weight || null, volume || null
    ]);
    
    const lineId = result.rows[0].lineid;
    
    console.log("Order line created successfully with ID:", lineId);
    res.status(201).json({ 
      message: 'Order line created successfully', 
      LineID: lineId 
    });
  } catch (err) {
    console.error("Order line creation failed:", err);
    res.status(500).json({ error: err.message });
  }
});

// PUT - Update an order line - CONVERTED
app.put('/orderLines/:id', async (req, res) => {
  console.log("PUT /orderLines/:id called, ID =", req.params.id);
  console.log("Incoming PUT body:", req.body);
  const { id } = req.params;
  const {
    orderid,
    ordernumber,
    linenumber,
    partnumber,
    description,
    quantity,
    uom,
    linestatus,
    productid,
    unitprice,
    weight,
    volume
  } = req.body;

  try {
    // Check if the table exists first
    const tableCheck = await pool.query(`
      SELECT COUNT(*) as count FROM information_schema.tables 
      WHERE table_schema = 'public' AND table_name = 'orderlines'
    `);

    if (parseInt(tableCheck.rows[0].count) === 0) {
      // Table doesn't exist, create it
      await ensureOrderLinesTable();
      return res.status(404).json({ message: 'Order line not found' });
    }
    
    const query = `
      UPDATE orderlines
      SET
        orderid = $2,
        ordernumber = $3,
        linenumber = $4,
        partnumber = $5,
        description = $6,
        quantity = $7,
        uom = $8,
        linestatus = $9,
        productid = $10,
        unitprice = $11,
        weight = $12,
        volume = $13,
        updatedat = NOW()
      WHERE lineid = $1
    `;

    await pool.query(query, [
    id, orderid, ordernumber, linenumber || 0, partnumber, description,
    quantity, uom || 'UNIT', linestatus || 'Pending', productid,
    unitprice || 0, weight || null, volume || null
  ]);

    console.log("Order line updated successfully!");
    res.status(200).json({ message: 'Order line updated successfully' });
  } catch (err) {
    console.error("Order line update failed:", err);
    res.status(500).json({ error: err.message });
  }
});

// DELETE - Delete an order line - CONVERTED
app.delete('/orderLines/:id', async (req, res) => {
  console.log("DELETE /orderLines/:id called, ID =", req.params.id);
  const { id } = req.params;
  try {
    // Check if the table exists first
    const tableCheck = await pool.query(`
      SELECT COUNT(*) as count FROM information_schema.tables 
      WHERE table_schema = 'public' AND table_name = 'orderlines'
    `);

    if (parseInt(tableCheck.rows[0].count) === 0) {
      console.log("OrderLines table does not exist yet.");
      return res.status(200).json({ message: 'Order line deleted successfully' });
    }

    const query = `DELETE FROM orderlines WHERE lineid = $1`;
    await pool.query(query, [id]);
    console.log("Order line deleted successfully!");
    res.status(200).json({ message: 'Order line deleted successfully' });
  } catch (err) {
    console.error("Order line deletion failed:", err);
    res.status(500).json({ error: err.message });
  }
});

/* ---------------------------------------------------------------
   Products (Inventory) Endpoints - CONVERTED TO POSTGRESQL
---------------------------------------------------------------- */

// GET /products - Retrieve all products from the DB with optional date filtering - CONVERTED
app.get('/products', async (req, res) => {
  console.log("GET /products called.");
  try {
    let queryStr = `SELECT 
      productid,
      name,
      sku,
      category,
      stock,
      description,
      createdat,
      updatedat,
      sellbydate,
      unitprice,
      weight,
      volume,
      CASE 
          WHEN sellbydate IS NULL THEN 'No Date Set'
          WHEN sellbydate < NOW() THEN 'Expired'
          WHEN sellbydate <= (NOW() + INTERVAL '30 days') THEN 'Expiring Soon'
          ELSE 'Fresh'
      END as sellbystatus
    FROM products`;
    
    const { startDate, endDate } = req.query;

    let params = [];
    if (startDate && endDate) {
      queryStr += ' WHERE createdat >= $1 AND createdat <= $2';
      params = [new Date(startDate), new Date(endDate)];
    }

    queryStr += ' ORDER BY productid DESC';

    const result = await pool.query(queryStr, params);
    console.log(`/products returned ${result.rows.length} records.`);
    res.status(200).json(result.rows);
  } catch (err) {
    console.error("Error fetching products:", err);
    res.status(500).json({ error: err.message });
  }
});

// POST /products - Add a new product - CONVERTED
app.post('/products', async (req, res) => {
  console.log("POST /products called. Incoming body:", req.body);
  const { name, sku, category, stock, description, sellByDate, unitPrice, weight, volume } = req.body;
  try {
    const query = `
      INSERT INTO products (name, sku, category, stock, description, sellbydate, unitprice, weight, volume, createdat, updatedat)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW())
      RETURNING productid
    `;

    const result = await pool.query(query, [
      name, sku, category, stock, description, sellByDate ? new Date(sellByDate) : null,
      unitPrice || null, weight || null, volume || null
    ]);

    const insertedId = result.rows[0].productid;
    console.log("Product added with ID:", insertedId);
    res.status(201).json({ message: 'Product added successfully', id: insertedId });
  } catch (err) {
    console.error("Failed to add product:", err);
    res.status(500).json({ error: err.message });
  }
});

// GET product by ID - CONVERTED
app.get('/products/:id', async (req, res) => {
  console.log("GET /products/:id called, ID =", req.params.id);
  const { id } = req.params;
  try {
    const query = `SELECT * FROM products WHERE productid = $1`;
    const result = await pool.query(query, [id]);

    if (result.rows.length === 0) {
      console.log("No product found with ID =", id);
      return res.status(404).json({ message: 'Product not found' });
    }

    console.log("Product record returned:", result.rows[0]);
    res.status(200).json(result.rows[0]);
  } catch (err) {
    console.error("Error fetching product:", err);
    res.status(500).json({ error: err.message });
  }
});

// PUT - Update a product - CONVERTED
app.put('/products/:id', async (req, res) => {
  console.log("PUT /products/:id called, ID =", req.params.id);
  console.log("Incoming PUT body:", req.body);
  const { id } = req.params;
  const { name, sku, category, stock, description, sellByDate, unitPrice, Name, SKU, Category, Stock, Description, SellByDate, UnitPrice } = req.body;

  try {
    // Handle both naming conventions (lowercase and uppercase)
    const actualStock = stock !== undefined ? stock : Stock;
    const actualName = name !== undefined ? name : Name;
    const actualSKU = sku !== undefined ? sku : SKU;
    const actualCategory = category !== undefined ? category : Category;
    const actualDescription = description !== undefined ? description : Description;
    const actualSellByDate = sellByDate !== undefined ? sellByDate : SellByDate;
    const actualUnitPrice = unitPrice !== undefined ? unitPrice : UnitPrice;

    console.log("BACKEND: Updating stock to:", actualStock);
    console.log("BACKEND: Weight:", req.body.weight, "Volume:", req.body.volume);

    const query = `
      UPDATE products
      SET
        name = COALESCE($2, name),
        sku = COALESCE($3, sku),
        category = COALESCE($4, category),
        stock = COALESCE($5, stock),
        description = COALESCE($6, description),
        sellbydate = COALESCE($7, sellbydate),
        unitprice = COALESCE($8, unitprice),
        weight = COALESCE($9, weight),
        volume = COALESCE($10, volume),
        updatedat = NOW()
      WHERE productid = $1
    `;

    await pool.query(query, [
      id, actualName, actualSKU, actualCategory, actualStock, actualDescription,
      actualSellByDate ? new Date(actualSellByDate) : null, actualUnitPrice || null, 
      parseFloat(req.body.weight) || null, parseFloat(req.body.volume) || null
    ]);

    // IMMEDIATE VERIFICATION - check if update actually worked
    const verifyResult = await pool.query('SELECT * FROM products WHERE productid = $1', [id]);

    if (verifyResult.rows.length > 0) {
      const updatedProduct = verifyResult.rows[0];
      console.log("BACKEND VERIFICATION: Updated stock is now:", updatedProduct.stock);
      
      if (actualStock !== undefined && updatedProduct.stock !== actualStock) {
        console.error("BACKEND ERROR: Stock update failed! Expected:", actualStock, "Got:", updatedProduct.stock);
        return res.status(500).json({ 
          message: 'Stock update failed',
          expected: actualStock,
          actual: updatedProduct.stock
        });
      }
    }

    console.log("Product updated successfully!");
    res.status(200).json({ message: 'Product updated successfully' });
  } catch (err) {
    console.error("Product update failed:", err);
    res.status(500).json({ error: err.message });
  }
});

// DELETE - Delete a product with cascade handling - CONVERTED
app.delete('/products/:id', async (req, res) => {
  console.log("DELETE /products/:id called, ID =", req.params.id);
  const { id } = req.params;
  
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    
    // First, delete from GroupProducts table (child records) if it exists
    try {
      await client.query('DELETE FROM groupproducts WHERE productid = $1', [id]);
      console.log("Removed product from groups");
    } catch (err) {
      // GroupProducts table might not exist, continue
      console.log("GroupProducts table doesn't exist or no records to delete");
    }
    
    // Then, delete the product itself (parent record)
    await client.query('DELETE FROM products WHERE productid = $1', [id]);
    console.log("Deleted product");
    
    // Commit the transaction
    await client.query('COMMIT');
    console.log("Product deleted successfully with cascade!");
    res.status(200).json({ message: 'Product deleted successfully' });
    
  } catch (err) {
    // Rollback transaction on error
    await client.query('ROLLBACK');
    console.error("Product deletion failed:", err);
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

/* ---------------------------------------------------------------
   VIRTUAL SHELVES API ENDPOINTS - CONVERTED TO POSTGRESQL
---------------------------------------------------------------- */

// Ensure Clients table exists
async function ensureClientsTable() {
  try {
    const tableCheck = await pool.query(`
      SELECT COUNT(*) as count FROM information_schema.tables 
      WHERE table_schema = 'public' AND table_name = 'clients'
    `);
    
    if (parseInt(tableCheck.rows[0].count) === 0) {
      console.log("Creating Clients table...");
      await pool.query(`
        CREATE TABLE clients (
          client_id SERIAL PRIMARY KEY,
          client_name VARCHAR(255),
          contact_email VARCHAR(255),
          contact_phone VARCHAR(50),
          address TEXT
        )
      `);
      console.log("Clients table created successfully!");
    } else {
      console.log("Clients table already exists.");
    }
  } catch (err) {
    console.error("Error checking/creating Clients table:", err);
  }
}

// Ensure Suppliers table exists
async function ensureSuppliersTable() {
  try {
    const tableCheck = await pool.query(`
      SELECT COUNT(*) as count FROM information_schema.tables 
      WHERE table_schema = 'public' AND table_name = 'suppliers'
    `);
    
    if (parseInt(tableCheck.rows[0].count) === 0) {
      console.log("Creating Suppliers table...");
      await pool.query(`
        CREATE TABLE suppliers (
          supplier_id SERIAL PRIMARY KEY,
          supplier_name VARCHAR(255),
          contact_email VARCHAR(255),
          contact_phone VARCHAR(50),
          address TEXT
        )
      `);
      console.log("Suppliers table created successfully!");
    } else {
      console.log("Suppliers table already exists.");
    }
  } catch (err) {
    console.error("Error checking/creating Suppliers table:", err);
  }
}

// Ensure VirtualShelves table exists
async function ensureVirtualShelvesTable() {
  try {
    const tableCheck = await pool.query(`
      SELECT COUNT(*) as count FROM information_schema.tables 
      WHERE table_schema = 'public' AND table_name = 'virtualshelves'
    `);
    
    if (parseInt(tableCheck.rows[0].count) === 0) {
      console.log("Creating VirtualShelves table...");
      await pool.query(`
        CREATE TABLE virtualshelves (
          id SERIAL PRIMARY KEY,
          name VARCHAR(255) NOT NULL,
          location VARCHAR(255),
          description TEXT,
          products TEXT, -- Stored as JSON array of product IDs
          createdat TIMESTAMP DEFAULT NOW(),
          updatedat TIMESTAMP DEFAULT NOW()
        )
      `);
      console.log("VirtualShelves table created successfully!");
    } else {
      console.log("VirtualShelves table already exists.");
    }
  } catch (err) {
    console.error("Error checking/creating VirtualShelves table:", err);
  }
}

// GET all virtual shelves - CONVERTED
app.get('/virtual-shelves', async (req, res) => {
  console.log("GET /virtual-shelves called.");
  try {
    // Ensure table exists before querying
    await ensureVirtualShelvesTable();
    
    const result = await pool.query('SELECT * FROM virtualshelves ORDER BY id DESC');
    
    // Parse the products JSON for each shelf
    const shelves = result.rows.map(shelf => {
      try {
        if (shelf.products) {
          shelf.products = JSON.parse(shelf.products);
        } else {
          shelf.products = [];
        }
      } catch (err) {
        console.warn("Warning: Could not parse products JSON for shelf:", err);
        shelf.products = [];
      }
      return shelf;
    });
    
    console.log("Records returned from /virtual-shelves:", shelves.length);
    res.status(200).json(shelves);
  } catch (err) {
    console.error("Error fetching virtual shelves:", err);
    // Return empty array on error to prevent frontend issues
    res.status(200).json([]);
  }
});

// GET a specific virtual shelf by ID - CONVERTED
app.get('/virtual-shelves/:id', async (req, res) => {
  console.log("GET /virtual-shelves/:id called, ID =", req.params.id);
  const { id } = req.params;
  try {
    await ensureVirtualShelvesTable();
    
    const query = `SELECT * FROM virtualshelves WHERE id = $1`;
    const result = await pool.query(query, [id]);

    if (result.rows.length === 0) {
      console.log("No virtual shelf found with ID =", id);
      return res.status(404).json({ message: 'Virtual shelf not found' });
    }

    const shelf = result.rows[0];
    
    // Parse the products JSON
    try {
      if (shelf.products) {
        shelf.products = JSON.parse(shelf.products);
      } else {
        shelf.products = [];
      }
    } catch (err) {
      console.warn("Warning: Could not parse products JSON for shelf:", err);
      shelf.products = [];
    }

    console.log("Virtual shelf record returned:", shelf);
    res.status(200).json(shelf);
  } catch (err) {
    console.error("Error fetching virtual shelf:", err);
    res.status(500).json({ error: err.message });
  }
});

// POST - Create a new virtual shelf - CONVERTED
app.post('/virtual-shelves', async (req, res) => {
  console.log("POST /virtual-shelves called. Incoming body:", req.body);
  const { name, location, description, products } = req.body;
  
  if (!name) {
    console.log("Shelf name is missing!");
    return res.status(400).json({ error: "Shelf name is required" });
  }
  
  try {
    // Ensure table exists before inserting
    await ensureVirtualShelvesTable();
    
    const query = `
      INSERT INTO virtualshelves (
        name, location, description, products, createdat, updatedat
      )
      VALUES (
        $1, $2, $3, $4, NOW(), NOW()
      )
      RETURNING id
    `;

    const result = await pool.query(query, [
      name, location || '', description || '', JSON.stringify(products || [])
    ]);
    
    const shelfId = result.rows[0].id;
    
    console.log("Virtual shelf created successfully with ID:", shelfId);
    res.status(201).json({ 
      message: 'Virtual shelf created successfully', 
      id: shelfId 
    });
  } catch (err) {
    console.error("Virtual shelf creation failed:", err);
    res.status(500).json({ error: err.message });
  }
});

// PUT - Update a virtual shelf - CONVERTED
app.put('/virtual-shelves/:id', async (req, res) => {
  console.log("PUT /virtual-shelves/:id called, ID =", req.params.id);
  console.log("Incoming PUT body:", req.body);
  const { id } = req.params;
  const { name, location, description, products } = req.body;

  try {
    await ensureVirtualShelvesTable();
    
    // Check if the shelf exists
    const checkResult = await pool.query('SELECT * FROM virtualshelves WHERE id = $1', [id]);

    if (checkResult.rows.length === 0) {
      console.log("No virtual shelf found with ID =", id);
      return res.status(404).json({ message: 'Virtual shelf not found' });
    }
    
    const query = `
      UPDATE virtualshelves
      SET
        name = COALESCE($2, name),
        location = COALESCE($3, location),
        description = COALESCE($4, description),
        products = COALESCE($5, products),
        updatedat = NOW()
      WHERE id = $1
    `;

    await pool.query(query, [
      id, name, location, description, products ? JSON.stringify(products) : null
    ]);

    console.log("Virtual shelf updated successfully!");
    res.status(200).json({ message: 'Virtual shelf updated successfully' });
  } catch (err) {
    console.error("Virtual shelf update failed:", err);
    res.status(500).json({ error: err.message });
  }
});

// DELETE - Delete a virtual shelf - CONVERTED
app.delete('/virtual-shelves/:id', async (req, res) => {
  console.log("DELETE /virtual-shelves/:id called, ID =", req.params.id);
  const { id } = req.params;
  try {
    await ensureVirtualShelvesTable();
    
    const query = `DELETE FROM virtualshelves WHERE id = $1`;
    const result = await pool.query(query, [id]);

    if (result.rowCount === 0) {
      console.log("No virtual shelf found with ID =", id);
      return res.status(404).json({ message: 'Virtual shelf not found' });
    }
    
    console.log("Virtual shelf deleted successfully!");
    res.status(200).json({ message: 'Virtual shelf deleted successfully' });
  } catch (err) {
    console.error("Virtual shelf deletion failed:", err);
    res.status(500).json({ error: err.message });
  }
});

/* ---------------------------------------------------------------
   INVENTORY API ENDPOINTS (ALIASES TO PRODUCTS) - CONVERTED
---------------------------------------------------------------- */

// GET all inventory items - maps to products endpoint - CONVERTED
app.get('/inventory', async (req, res) => {
  console.log("GET /inventory called - redirecting to products endpoint");
  try {
    // Just pass through any query params
    let query = 'SELECT * FROM products';
    let params = [];
    if (req.query.startDate && req.query.endDate) {
      query = 'SELECT * FROM products WHERE createdat >= $1 AND createdat <= $2';
      params = [req.query.startDate, req.query.endDate];
    }

    query += ' ORDER BY productid DESC';
    const result = await pool.query(query, params);
    console.log("Records returned from /inventory:", result.rows.length);
    res.status(200).json(result.rows);
  } catch (err) {
    console.error("Error fetching inventory items:", err);
    res.status(500).json({ error: err.message });
  }
});

// GET a single inventory item by ID - CONVERTED
app.get('/inventory/:id', async (req, res) => {
  console.log("GET /inventory/:id called, ID =", req.params.id);
  const { id } = req.params;
  try {
    const query = `SELECT * FROM products WHERE productid = $1`;
    const result = await pool.query(query, [id]);

    if (result.rows.length === 0) {
      console.log("No product found with ID =", id);
      return res.status(404).json({ message: 'Product not found' });
    }

    console.log("Product record returned:", result.rows[0]);
    res.status(200).json(result.rows[0]);
  } catch (err) {
    console.error("Error fetching product:", err);
    res.status(500).json({ error: err.message });
  }
});

// POST - Create a new inventory item - CONVERTED
app.post('/inventory', async (req, res) => {
  console.log("POST /inventory called - redirecting to products endpoint");
  try {
    // Forward the request to the products endpoint
    const { name, sku, category, stock, description } = req.body;
    
    const query = `
      INSERT INTO products (
        name, sku, category, stock, description, createdat, updatedat
      )
      VALUES (
        $1, $2, $3, $4, $5, NOW(), NOW()
      )
      RETURNING productid
    `;
    
    const result = await pool.query(query, [name, sku, category, stock || 0, description]);
    const productId = result.rows[0].productid;
    
    console.log("Product created successfully with ID:", productId);
    res.status(201).json({ 
      message: 'Product created successfully', 
      ProductID: productId 
    });
  } catch (err) {
    console.error("Product creation failed:", err);
    res.status(500).json({ error: err.message });
  }
});

// PUT - Update an inventory item - CONVERTED
app.put('/inventory/:id', async (req, res) => {
  console.log("PUT /inventory/:id called, ID =", req.params.id);
  const { id } = req.params;
  try {
    // Forward to products endpoint
    const { Name, SKU, Category, Stock, Description } = req.body;
    
    const query = `
      UPDATE products
      SET
        name = COALESCE($2, name),
        sku = COALESCE($3, sku),
        category = COALESCE($4, category),
        stock = COALESCE($5, stock),
        description = COALESCE($6, description),
        updatedat = NOW()
      WHERE productid = $1
    `;

    await pool.query(query, [id, Name, SKU, Category, Stock, Description]);
    console.log("Product updated successfully!");
    res.status(200).json({ message: 'Product updated successfully' });
  } catch (err) {
    console.error("Product update failed:", err);
    res.status(500).json({ error: err.message });
  }
});

// DELETE - Delete an inventory item - CONVERTED
app.delete('/inventory/:id', async (req, res) => {
  console.log("DELETE /inventory/:id called, ID =", req.params.id);
  const { id } = req.params;
  try {
    // Forward to products endpoint
    const query = `DELETE FROM products WHERE productid = $1`;
    await pool.query(query, [id]);
    console.log("Product deleted successfully!");
    res.status(200).json({ message: 'Product deleted successfully' });
  } catch (err) {
    console.error("Product deletion failed:", err);
    res.status(500).json({ error: err.message });
  }
});

/* ---------------------------------------------------------------
   NEW: REPORTS ENDPOINTS - CONVERTED TO POSTGRESQL
---------------------------------------------------------------- */

// Ensure Reports table exists
async function ensureReportsTable() {
  try {
    const tableCheck = await pool.query(`
      SELECT COUNT(*) as count FROM information_schema.tables 
      WHERE table_schema = 'public' AND table_name = 'reports'
    `);
    
    if (parseInt(tableCheck.rows[0].count) === 0) {
      console.log("Creating Reports table...");
      await pool.query(`
        CREATE TABLE reports (
          id SERIAL PRIMARY KEY,
          userid INT NOT NULL,
          name VARCHAR(255) NOT NULL,
          type VARCHAR(50),
          format VARCHAR(50),
          description VARCHAR(500),
          columns TEXT,
          filters TEXT,
          created TIMESTAMP DEFAULT NOW(),
          lastrun TIMESTAMP,
          datasource VARCHAR(100),
          createdat TIMESTAMP DEFAULT NOW(),
          updatedat TIMESTAMP DEFAULT NOW()
        )
      `);
      console.log("✅ Reports table created successfully!");
    } else {
      console.log("Reports table already exists.");
    }
  } catch (err) {
    console.error("❌ Error checking/creating Reports table:", err);
  }
}

// Ensure UserPreferences table exists
async function ensureUserPreferencesTable() {
  try {
    const tableCheck = await pool.query(`
      SELECT COUNT(*) as count FROM information_schema.tables 
      WHERE table_schema = 'public' AND table_name = 'userpreferences'
    `);
    
    if (parseInt(tableCheck.rows[0].count) === 0) {
      console.log("Creating UserPreferences table...");
      await pool.query(`
        CREATE TABLE userpreferences (
          id SERIAL PRIMARY KEY,
          userid INT NOT NULL,
          defaultdaterange TEXT,
          defaultreporttype VARCHAR(50),
          favoritereports TEXT,
          recentreports TEXT,
          createdat TIMESTAMP DEFAULT NOW(),
          updatedat TIMESTAMP DEFAULT NOW()
        )
      `);
      console.log("✅ UserPreferences table created successfully!");
    } else {
      console.log("UserPreferences table already exists.");
    }
  } catch (err) {
    console.error("❌ Error checking/creating UserPreferences table:", err);
  }
}

// Ensure SavedImports table exists
async function ensureSavedImportsTable() {
  try {
    const tableCheck = await pool.query(`
      SELECT COUNT(*) as count FROM information_schema.tables 
      WHERE table_schema = 'public' AND table_name = 'savedimports'
    `);
    
    if (parseInt(tableCheck.rows[0].count) === 0) {
      console.log("Creating SavedImports table...");
      await pool.query(`
        CREATE TABLE savedimports (
          id SERIAL PRIMARY KEY,
          userid INT NOT NULL,
          filename VARCHAR(255) NOT NULL,
          dateimported TIMESTAMP DEFAULT NOW(),
          totalrows INT,
          mappings TEXT,
          dataschema TEXT
        )
      `);
      console.log("✅ SavedImports table created successfully!");
    } else {
      console.log("SavedImports table already exists.");
    }
  } catch (err) {
    console.error("❌ Error checking/creating SavedImports table:", err);
  }
}

// GET all reports - CONVERTED
app.get('/reports', async (req, res) => {
  console.log("GET /reports called.");
  try {
    await ensureReportsTable();
    const result = await pool.query('SELECT * FROM reports ORDER BY id DESC');
    console.log("Records returned from /reports:", result.rows.length);
    res.status(200).json(result.rows);
  } catch (err) {
    console.error("❌ Error fetching reports:", err);
    res.status(500).json({ error: err.message });
  }
});

// GET reports for a specific user - CONVERTED
app.get('/reports/user/:userId', async (req, res) => {
  console.log("GET /reports/user/:userId called, userId =", req.params.userId);
  const { userId } = req.params;
  try {
    await ensureReportsTable();
    const query = `SELECT * FROM reports WHERE userid = $1 ORDER BY id DESC`;
    const result = await pool.query(query, [userId]);

    console.log(`✅ ${result.rows.length} reports found for userId=${userId}`);
    res.status(200).json(result.rows);
  } catch (err) {
    console.error("❌ Error fetching user-specific reports:", err);
    res.status(500).json({ error: err.message });
  }
});

// POST - Create a new report - CONVERTED
app.post('/reports', async (req, res) => {
  console.log("POST /reports called. Incoming body:", req.body);
  const {
    userId, name, type, format, description, columns, filters, 
    created, lastRun, dataSource
  } = req.body;
  
  try {
    await ensureReportsTable();
    const query = `
      INSERT INTO reports (
        userid, name, type, format, description, columns, filters, 
        created, lastrun, datasource
      )
      VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10
      )
      RETURNING id
    `;

    const result = await pool.query(query, [
      userId, name, type, format, description, JSON.stringify(columns),
      JSON.stringify(filters), created ? new Date(created) : new Date(), 
      lastRun ? new Date(lastRun) : null, dataSource
    ]);

    const insertedId = result.rows[0].id;
    console.log("✅ Report created successfully with ID:", insertedId);
    
    res.status(201).json({ 
      message: 'Report created successfully', 
      id: insertedId 
    });
  } catch (err) {
    console.error("❌ Report creation failed:", err);
    res.status(500).json({ error: err.message });
  }
});

// GET a single report by ID - CONVERTED
app.get('/reports/:id', async (req, res) => {
  console.log("GET /reports/:id called, ID =", req.params.id);
  const { id } = req.params;
  try {
    await ensureReportsTable();
    const query = `SELECT * FROM reports WHERE id = $1`;
    const result = await pool.query(query, [id]);

    if (result.rows.length === 0) {
      console.log("❌ No report found with ID =", id);
      return res.status(404).json({ message: 'Report not found' });
    }

    // Parse JSON columns
    const report = result.rows[0];
    if (report.columns) {
      try {
        report.columns = JSON.parse(report.columns);
      } catch (err) {
        console.warn("Warning: Could not parse columns JSON for report:", err);
      }
    }
    
    if (report.filters) {
      try {
        report.filters = JSON.parse(report.filters);
      } catch (err) {
        console.warn("Warning: Could not parse filters JSON for report:", err);
      }
    }

    console.log("✅ Report record returned:", report);
    res.status(200).json(report);
  } catch (err) {
    console.error("❌ Error fetching report:", err);
    res.status(500).json({ error: err.message });
  }
});

// PUT - Update a report - CONVERTED
app.put('/reports/:id', async (req, res) => {
  console.log("PUT /reports/:id called, ID =", req.params.id);
  console.log("Incoming PUT body:", req.body);
  const { id } = req.params;
  const {
    userId, name, type, format, description, columns, filters, lastRun, dataSource
  } = req.body;

  try {
    await ensureReportsTable();
    const query = `
      UPDATE reports
      SET
        userid = $2,
        name = $3,
        type = $4,
        format = $5,
        description = $6,
        columns = $7,
        filters = $8,
        lastrun = $9,
        datasource = $10,
        updatedat = NOW()
      WHERE id = $1
    `;

    await pool.query(query, [
      id, userId, name, type, format, description, JSON.stringify(columns),
      JSON.stringify(filters), lastRun ? new Date(lastRun) : null, dataSource
    ]);

    console.log("✅ Report updated successfully!");
    res.status(200).json({ message: 'Report updated successfully' });
  } catch (err) {
    console.error("❌ Report update failed:", err);
    res.status(500).json({ error: err.message });
  }
});

// DELETE - Delete a report - CONVERTED
app.delete('/reports/:id', async (req, res) => {
  console.log("DELETE /reports/:id called, ID =", req.params.id);
  const { id } = req.params;
  try {
    await ensureReportsTable();
    const query = `DELETE FROM reports WHERE id = $1`;
    await pool.query(query, [id]);
    console.log("✅ Report deleted successfully!");
    res.status(200).json({ message: 'Report deleted successfully' });
  } catch (err) {
    console.error("❌ Report deletion failed:", err);
    res.status(500).json({ error: err.message });
  }
});

// GET data sources for reports
app.get('/data-sources', (req, res) => {
  console.log("GET /data-sources called.");
  try {
    const dataSources = [
      { id: "inventory_data", name: "Inventory Data" },
      { id: "sales_data", name: "Sales Data" },
      { id: "customer_data", name: "Customer Data" },
      { id: "order_data", name: "Order Data" },
      { id: "virtual_shelves", name: "Virtual Shelf Data" },
      { id: "intake_schedule", name: "Intake Schedule Data" },
      { id: "customs_data", name: "Customs Data" },
      { id: "shipping_data", name: "Shipping Data" },
      { id: "logistics_data", name: "Logistics Data" },
      { id: "trade_analytics", name: "Trade Analytics" }
    ];
    
    res.status(200).json(dataSources);
  } catch (err) {
    console.error("❌ Error fetching data sources:", err);
    res.status(500).json({ error: err.message });
  }
});

// GET user preferences - CONVERTED
app.get('/user-preferences/:userId', async (req, res) => {
  console.log("GET /user-preferences/:userId called, userId =", req.params.userId);
  const { userId } = req.params;
  try {
    await ensureUserPreferencesTable();
    const query = `SELECT * FROM userpreferences WHERE userid = $1`;
    const result = await pool.query(query, [userId]);

    if (result.rows.length === 0) {
      // Return default preferences if none exist
      const defaultPrefs = {
        userId: parseInt(userId),
        defaultDateRange: [
          new Date(new Date().setDate(new Date().getDate() - 30)).toISOString(),
          new Date().toISOString()
        ],
        defaultReportType: "inventory",
        favoriteReports: [],
        recentReports: []
      };
      
      console.log("No preferences found, returning defaults");
      return res.status(200).json(defaultPrefs);
    }

    // Parse JSON fields
    const prefs = result.rows[0];
    try {
      if (prefs.defaultdaterange) {
        prefs.defaultDateRange = JSON.parse(prefs.defaultdaterange);
      }
      if (prefs.favoritereports) {
        prefs.favoriteReports = JSON.parse(prefs.favoritereports);
      }
      if (prefs.recentreports) {
        prefs.recentReports = JSON.parse(prefs.recentreports);
      }
    } catch (parseErr) {
      console.warn("Warning: Could not parse JSON in user preferences:", parseErr);
    }

    console.log("✅ User preferences returned:", prefs);
    res.status(200).json(prefs);
  } catch (err) {
    console.error("❌ Error fetching user preferences:", err);
    res.status(500).json({ error: err.message });
  }
});

// PUT user preferences - CONVERTED
app.put('/user-preferences/:userId', async (req, res) => {
  console.log("PUT /user-preferences/:userId called, userId =", req.params.userId);
  console.log("Incoming PUT body:", req.body);
  const { userId } = req.params;
  const { defaultDateRange, defaultReportType, favoriteReports, recentReports } = req.body;

  try {
    await ensureUserPreferencesTable();
    
    // Check if user preferences already exist
    const checkQuery = `SELECT COUNT(*) as count FROM userpreferences WHERE userid = $1`;
    const checkResult = await pool.query(checkQuery, [userId]);
    
    let query;
    if (parseInt(checkResult.rows[0].count) > 0) {
      // Update existing preferences
      query = `
        UPDATE userpreferences
        SET
          defaultdaterange = $2,
          defaultreporttype = $3,
          favoritereports = $4,
          recentreports = $5,
          updatedat = NOW()
        WHERE userid = $1
      `;
    } else {
      // Insert new preferences
      query = `
        INSERT INTO userpreferences (
          userid, defaultdaterange, defaultreporttype, favoritereports, recentreports, createdat, updatedat
        )
        VALUES (
          $1, $2, $3, $4, $5, NOW(), NOW()
        )
      `;
    }

    await pool.query(query, [
      userId, JSON.stringify(defaultDateRange), defaultReportType,
      JSON.stringify(favoriteReports || []), JSON.stringify(recentReports || [])
    ]);

    console.log("✅ User preferences updated successfully!");
    res.status(200).json({ message: 'User preferences updated successfully' });
  } catch (err) {
    console.error("❌ User preferences update failed:", err);
    res.status(500).json({ error: err.message });
  }
});

// GET saved imports - CONVERTED
app.get('/saved-imports/:userId', async (req, res) => {
  console.log("GET /saved-imports/:userId called, userId =", req.params.userId);
  const { userId } = req.params;
  try {
    await ensureSavedImportsTable();
    
    // Check column names to determine which query to use
    const columnsResult = await pool.query(`
      SELECT column_name 
      FROM information_schema.columns 
      WHERE table_schema = 'public' AND table_name = 'savedimports'
    `);
    
    const columnNames = columnsResult.rows.map(r => r.column_name.toLowerCase());
    const hasDataSchema = columnNames.includes('dataschema');
    const hasTotalRows = columnNames.includes('totalrows');
    
    const query = `SELECT * FROM savedimports WHERE userid = $1 ORDER BY dateimported DESC`;
    const result = await pool.query(query, [userId]);

    console.log(`✅ ${result.rows.length} saved imports found for userId=${userId}`);
    
    // Parse JSON fields and handle different column naming
    const imports = result.rows.map(imp => {
      try {
        if (imp.mappings) {
          imp.mappings = JSON.parse(imp.mappings);
        }
        
        // Handle schema/dataSchema column
        if (hasDataSchema && imp.dataschema) {
          imp.schema = JSON.parse(imp.dataschema);
          delete imp.dataschema; // Remove dataSchema field for client compatibility
        } else if (imp.schema) {
          imp.schema = JSON.parse(imp.schema);
        }
        
        // Handle rowCount/totalRows column
        if (hasTotalRows && imp.totalrows !== undefined) {
          imp.rowCount = imp.totalrows;
          delete imp.totalrows; // Remove totalRows field for client compatibility
        }
      } catch (parseErr) {
        console.warn("Warning: Could not parse JSON in saved import:", parseErr);
      }
      return imp;
    });
    
    res.status(200).json(imports);
  } catch (err) {
    console.error("❌ Error fetching saved imports:", err);
    res.status(500).json({ error: err.message });
  }
});

// POST save a new import - CONVERTED
app.post('/saved-imports', async (req, res) => {
  console.log("POST /saved-imports called. Incoming body:", req.body);
  const { userId, fileName, dateImported, rowCount, mappings, schema } = req.body;
  
  try {
    await ensureSavedImportsTable();
    
    const query = `
      INSERT INTO savedimports (
        userid, filename, dateimported, totalrows, mappings, dataschema
      )
      VALUES (
        $1, $2, $3, $4, $5, $6
      )
      RETURNING id
    `;

    const result = await pool.query(query, [
      userId, fileName, dateImported ? new Date(dateImported) : new Date(),
      rowCount, JSON.stringify(mappings), JSON.stringify(schema)
    ]);

    const insertedId = result.rows[0].id;
    console.log("✅ Import saved successfully with ID:", insertedId);
    
    res.status(201).json({ 
      message: 'Import saved successfully', 
      id: insertedId 
    });
  } catch (err) {
    console.error("❌ Failed to save import:", err);
    res.status(500).json({ error: err.message });
  }
});

/* ---------------------------------------------------------------
   NEW: GROUPING ENDPOINTS - CONVERTED TO POSTGRESQL
---------------------------------------------------------------- */

// Ensure ProductGroups table exists
async function ensureProductGroupsTable() {
  try {
    const tableCheck = await pool.query(`
      SELECT COUNT(*) as count FROM information_schema.tables 
      WHERE table_schema = 'public' AND table_name = 'productgroups'
    `);
    
    if (parseInt(tableCheck.rows[0].count) === 0) {
      console.log("Creating ProductGroups table...");
      await pool.query(`
        CREATE TABLE productgroups (
          groupid SERIAL PRIMARY KEY,
          groupname VARCHAR(255) NOT NULL,
          userid INT,
          createdat TIMESTAMP DEFAULT NOW()
        )
      `);
      console.log("✅ ProductGroups table created successfully!");
    } else {
      console.log("ProductGroups table already exists.");
    }

    // Check for GroupProducts table
    const groupProductsTableCheck = await pool.query(`
      SELECT COUNT(*) as count FROM information_schema.tables 
      WHERE table_schema = 'public' AND table_name = 'groupproducts'
    `);
    
    if (parseInt(groupProductsTableCheck.rows[0].count) === 0) {
      console.log("Creating GroupProducts table...");
      await pool.query(`
        CREATE TABLE groupproducts (
          groupid INT NOT NULL,
          productid INT NOT NULL,
          PRIMARY KEY (groupid, productid),
          CONSTRAINT fk_groupproducts_group FOREIGN KEY (groupid) REFERENCES productgroups(groupid) ON DELETE CASCADE
        )
      `);
      console.log("✅ GroupProducts table created successfully!");
    } else {
      console.log("GroupProducts table already exists.");
    }
  } catch (err) {
    console.error("❌ Error checking/creating ProductGroups tables:", err);
  }
}

// GET /product-groups - Retrieve all groups with their associated product IDs - CONVERTED
app.get('/product-groups', async (req, res) => {
  try {
    await ensureProductGroupsTable();
    
    // Get all groups
    const groupsResult = await pool.query('SELECT * FROM productgroups ORDER BY groupid DESC');
    const groups = groupsResult.rows;

    // Get all group-product mappings
    const mappingsResult = await pool.query('SELECT * FROM groupproducts');
    const mappings = mappingsResult.rows;

    // Construct a mapping of GroupID to array of ProductIDs
    const groupProductsMap = {};
    mappings.forEach(m => {
      if (groupProductsMap[m.groupid]) {
        groupProductsMap[m.groupid].push(m.productid);
      } else {
        groupProductsMap[m.groupid] = [m.productid];
      }
    });

    // Combine each group with its productIDs
    const groupsWithProducts = groups.map(group => ({
      ...group,
      productIDs: groupProductsMap[group.groupid] || []
    }));

    res.status(200).json(groupsWithProducts);
  } catch (err) {
    console.error("❌ Error fetching groups:", err);
    res.status(500).json({ error: err.message });
  }
});

// POST /product-groups - Create a new group with a name and an array of product IDs - CONVERTED
app.post('/product-groups', async (req, res) => {
  const { groupName, userID, productIDs } = req.body;
  if (!groupName) {
    return res.status(400).json({ error: "Group name is required." });
  }
  
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await ensureProductGroupsTable();
    
    // Insert into ProductGroups
    const result = await client.query(`
      INSERT INTO productgroups (groupname, userid, createdat)
      VALUES ($1, $2, NOW())
      RETURNING groupid
    `, [groupName, userID || null]);
    
    const groupID = result.rows[0].groupid;
    
    // If productIDs are provided, insert into GroupProducts
    if (productIDs && productIDs.length > 0) {
      for (const productID of productIDs) {
        await client.query('INSERT INTO groupproducts (groupid, productid) VALUES ($1, $2)', [groupID, productID]);
      }
    }
    
    await client.query('COMMIT');
    res.status(201).json({ message: "Group created successfully", GroupID: groupID });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error("❌ Error creating group:", err);
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

// PUT /product-groups/:groupID - Update a group's name and its associated product IDs - CONVERTED
app.put('/product-groups/:groupID', async (req, res) => {
  const { groupID } = req.params;
  const { groupName, productIDs } = req.body;
  
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await ensureProductGroupsTable();
    
    // Update the group name
    await client.query('UPDATE productgroups SET groupname = $1 WHERE groupid = $2', [groupName, groupID]);

    // Remove existing mappings
    await client.query('DELETE FROM groupproducts WHERE groupid = $1', [groupID]);

    // Insert new mappings if provided
    if (productIDs && productIDs.length > 0) {
      for (const productID of productIDs) {
        await client.query('INSERT INTO groupproducts (groupid, productid) VALUES ($1, $2)', [groupID, productID]);
      }
    }
    
    await client.query('COMMIT');
    res.status(200).json({ message: "Group updated successfully" });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error("❌ Error updating group:", err);
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

// DELETE /product-groups/:groupID - Delete a group and its product mappings - CONVERTED
app.delete('/product-groups/:groupID', async (req, res) => {
  const { groupID } = req.params;
  
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await ensureProductGroupsTable();

    // Delete mappings first (child records)
    await client.query('DELETE FROM groupproducts WHERE groupid = $1', [groupID]);
    
    // Delete group (parent record)
    await client.query('DELETE FROM productgroups WHERE groupid = $1', [groupID]);

    await client.query('COMMIT');
    res.status(200).json({ message: "Group deleted successfully" });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error("❌ Error deleting group:", err);
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

/* ---------------------------------------------------------------
   NEW: DATABASE CHECK ENDPOINT (FOR DEBUGGING) - CONVERTED
---------------------------------------------------------------- */
app.get('/api/check-db', async (req, res) => {
  try {
    // Test a simple query
    const result = await pool.query('SELECT version()');
    const dbVersion = result.rows[0].version;
    
    // Check tables
    const tablesResult = await pool.query(`
      SELECT table_name 
      FROM information_schema.tables 
      WHERE table_schema = 'public'
    `);
    
    const tables = tablesResult.rows.map(t => t.table_name);
    
    // Check SavedImports columns if it exists
    let savedImportsColumns = [];
    if (tables.includes('savedimports')) {
      const columnsResult = await pool.query(`
        SELECT column_name 
        FROM information_schema.columns 
        WHERE table_schema = 'public' AND table_name = 'savedimports'
      `);
      savedImportsColumns = columnsResult.rows.map(c => c.column_name);
    }
    
    res.status(200).json({
      status: 'connected',
      dbVersion: dbVersion,
      tables: tables,
      savedImportsColumns: savedImportsColumns
    });
  } catch (err) {
    console.error("❌ Database connection test failed:", err);
    res.status(500).json({ 
      status: 'error',
      message: err.message
    });
  }
});

/* ---------------------------------------------------------------
   NEW: UN/LOCODE ENDPOINTS
   These endpoints expose the subdivisions (combined UN/LOCODE data)
   that were scraped and saved as subdivisions.json in the parent folder.
---------------------------------------------------------------- */
// Build the path to subdivisions.json which is located one level up
const subdivisionsDataPath = path.join(__dirname, '..', 'subdivisions.json');
let subdivisionsData = [];
try {
  const rawData = fs.readFileSync(subdivisionsDataPath, 'utf8');
  subdivisionsData = JSON.parse(rawData);
  console.log(`Loaded ${subdivisionsData.length} subdivision records.`);
} catch (error) {
  console.error('Error loading subdivisions data:', error);
}

// Endpoint to get all subdivisions (combined UN/LOCODE entries)
app.get('/api/unlocodes', (req, res) => {
  res.json(subdivisionsData);
});

// Endpoint for real-time search on subdivisions using query parameter "q"
app.get('/api/search-unlocodes', (req, res) => {
  const query = req.query.q;
  if (!query) {
    return res.status(400).json({ error: 'Query parameter "q" is required.' });
  }
  const lowerQuery = query.toLowerCase();
  // Filter entries that include the query in any of the three columns:
  let results = subdivisionsData.filter(entry => {
    const c1 = (entry.column1 || '').toLowerCase();
    const c2 = (entry.column2 || '').toLowerCase();
    const c3 = (entry.column3 || '').toLowerCase();
    return c1.includes(lowerQuery) || c2.includes(lowerQuery) || c3.includes(lowerQuery);
  });

  // Rank the results
  results.sort((a, b) => rankEntry(b, lowerQuery) - rankEntry(a, lowerQuery));
  res.json(results);
});

function rankEntry(entry, lowerQuery) {
  const c1 = (entry.column1 || '').toLowerCase();
  const c2 = (entry.column2 || '').toLowerCase();
  const c3 = (entry.column3 || '').toLowerCase();
  let score = 0;
  // Give a high score if the country code starts with the query
  if (c1.startsWith(lowerQuery)) {
    score += 5;
  } else if (c1.includes(lowerQuery)) {
    score += 1;
  }
  // If the numeric or other code starts with query, add a medium boost
  if (c2.startsWith(lowerQuery)) {
    score += 4;
  } else if (c2.includes(lowerQuery)) {
    score += 1;
  }
  // For city/subdivision name
  if (c3.startsWith(lowerQuery)) {
    score += 3;
  } else if (c3.includes(lowerQuery)) {
    score += 1;
  }
  return score;
}

/* ---------------------------------------------------------------
   Global error handler
---------------------------------------------------------------- */
app.use((err, req, res, next) => {
  console.error('Global error handler caught:', err);
  res.status(500).json({ 
    error: err.message
  });
});

/* ---------------------------------------------------------------
   PO INVOICES API ENDPOINTS - CONVERTED TO POSTGRESQL
---------------------------------------------------------------- */

// Ensure POInvoice table exists
async function ensurePOInvoiceTable() {
  try {
    const tableCheck = await pool.query(`
      SELECT COUNT(*) as count FROM information_schema.tables 
      WHERE table_schema = 'public' AND table_name = 'poinvoice'
    `);
    
    if (parseInt(tableCheck.rows[0].count) === 0) {
      console.log("Creating POInvoice table...");
      await pool.query(`
        CREATE TABLE poinvoice (
          poinvoiceid SERIAL PRIMARY KEY,
          orderid INT NOT NULL,
          invoiceno VARCHAR(255),
          invoicedate TIMESTAMP,
          vendorref VARCHAR(255),
          vendorid INT,
          currency VARCHAR(10),
          foreignvalue DECIMAL(18,2),
          roe DECIMAL(10,4),
          roedate TIMESTAMP,
          randamount DECIMAL(18,2),
          taxamount DECIMAL(18,2),
          transactiontype INT,
          paymentterms VARCHAR(100),
          bankdetails TEXT,
          insurancedetails TEXT,
          apn VARCHAR(255),
          incoterm VARCHAR(50),
          hscode VARCHAR(50),
          countryoforigin VARCHAR(100),
          lcnumber VARCHAR(255),
          transportmode VARCHAR(50),
          containertype VARCHAR(50),
          containercount INT,
          portofloading VARCHAR(255),
          portofdischarge VARCHAR(255),
          vesselname VARCHAR(255),
          blnumber VARCHAR(255),
          grossweight DECIMAL(10,2),
          netweight DECIMAL(10,2),
          volume DECIMAL(10,2),
          packagecount INT,
          packagetype VARCHAR(50),
          dimensions VARCHAR(100),
          certificateoforigin VARCHAR(255),
          customsdeclaration VARCHAR(255),
          specialinstructions TEXT,
          additionaldetails TEXT,
          expectedstockstatus VARCHAR(50) DEFAULT 'planning',
          createdat TIMESTAMP DEFAULT NOW(),
          updatedat TIMESTAMP DEFAULT NOW(),
          CONSTRAINT fk_poinvoice_order FOREIGN KEY (orderid) REFERENCES orders(orderid) ON DELETE CASCADE
        )
      `);
      console.log("POInvoice table created successfully!");
    } else {
      console.log("POInvoice table already exists.");
      
      // Check if ExpectedStockStatus column exists (for existing installations)
      const columnCheck = await pool.query(`
        SELECT COUNT(*) as count 
        FROM information_schema.columns 
        WHERE table_schema = 'public' AND table_name = 'poinvoice' AND column_name = 'expectedstockstatus'
      `);

      if (parseInt(columnCheck.rows[0].count) === 0) {
        console.log("Adding ExpectedStockStatus column to existing POInvoice table...");
        await pool.query(`
          ALTER TABLE poinvoice 
          ADD COLUMN expectedstockstatus VARCHAR(50) DEFAULT 'planning'
        `);
        console.log("ExpectedStockStatus column added successfully!");
      } else {
        console.log("ExpectedStockStatus column already exists.");
      }
    }
  } catch (err) {
    console.error("Error checking/creating POInvoice table:", err);
  }
}

// GET commercial invoices for an order - CONVERTED
app.get('/api/po-invoices', async (req, res) => {
  console.log("GET /api/po-invoices called with query:", req.query);
  try {
    const { orderid } = req.query;
    
    if (!orderid) {
      console.log("No orderID provided");
      return res.status(200).json([]);
    }

    await ensurePOInvoiceTable();

    const query = `
      SELECT 
        poinvoiceid, orderid, invoiceno, vendorref, vendorid, currency,
        foreignvalue, paymentterms, apn, incoterm, hscode, countryoforigin,
        transportmode, containertype, containercount, portofloading, 
        portofdischarge, vesselname, roe, randamount, lcnumber, 
        transactiontype, bankdetails, insurancedetails, grossweight,
        netweight, volume, packagecount, certificateoforigin,
        customsdeclaration, specialinstructions, additionaldetails,
        invoicedate,
        roedate,
        createdat, updatedat,
        expectedstockstatus
      FROM poinvoice 
      WHERE orderid = $1 
      ORDER BY poinvoiceid DESC
    `;
    
    const result = await pool.query(query, [orderid]);

    console.log(`Found ${result.rows.length} invoices for order ${orderid}`);
    res.status(200).json(result.rows);
    
  } catch (err) {
    console.error("Error fetching invoices:", err);
    res.status(200).json([]);
  }
});

// POST - Create new invoice - CONVERTED
app.post('/api/po-invoices', async (req, res) => {
  console.log("POST /api/po-invoices called with body:", req.body);
  try {
    await ensurePOInvoiceTable();
    
    const invoiceData = req.body;
    const isUpdate = invoiceData.poinvoiceid;
    
    // Always use current date for invoice creation
    const today = new Date();
    const cleanInvoiceDate = `${today.getFullYear()}-${String(today.getMonth() + 1).padStart(2, '0')}-${String(today.getDate()).padStart(2, '0')}`;
    console.log("Today's actual date:", cleanInvoiceDate);
    
    let query;
    let params;
    
    if (isUpdate) {
      // UPDATE existing invoice - DON'T change the original invoice date
      query = `
        UPDATE poinvoice SET
          vendorref = $2,
          vendorid = $3,
          currency = $4,
          foreignvalue = $5,
          paymentterms = $6,
          updatedat = NOW()
        WHERE poinvoiceid = $1
      `;
      params = [
        invoiceData.poinvoiceid,
        invoiceData.vendorref || '',
        invoiceData.vendorid ? parseInt(invoiceData.vendorid) : null,
        invoiceData.currency || 'USD',
        invoiceData.foreignvalue || 0,
        invoiceData.paymentterms || 'Net 30'
      ];
    } else {
      // CREATE new invoice with today's date
      query = `
        INSERT INTO poinvoice (
          orderid, invoiceno, invoicedate, vendorref, vendorid, currency, 
          foreignvalue, paymentterms, apn, incoterm, hscode, countryoforigin,
          transportmode, containertype, containercount, portofloading, portofdischarge,
          vesselname, roe, roedate, randamount, lcnumber, transactiontype,
          bankdetails, insurancedetails, grossweight, netweight, volume, packagecount,
          certificateoforigin, customsdeclaration, specialinstructions, additionaldetails,
          expectedstockstatus, createdat, updatedat
        )
        VALUES (
          $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17,
          $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, 
          $33, $34, NOW(), NOW()
        )
        RETURNING poinvoiceid
      `;
      
      params = [
        invoiceData.orderid,
        invoiceData.invoiceno || '',
        cleanInvoiceDate,
        invoiceData.vendorref || '',
        invoiceData.vendorid ? parseInt(invoiceData.vendorid) : null,
        invoiceData.currency || 'USD',
        invoiceData.foreignvalue || 0,
        invoiceData.paymentterms || 'Net 30',
        invoiceData.apn || '',
        invoiceData.incoterm || '',
        invoiceData.hscode || '',
        invoiceData.countryoforigin || '',
        invoiceData.transportmode || '',
        invoiceData.containertype || '',
        invoiceData.containercount || 1,
        invoiceData.portofloading || '',
        invoiceData.portofdischarge || '',
        invoiceData.vesselname || '',
        invoiceData.roe || 1.0000,
        sanitizeDate(invoiceData.roedate),
        invoiceData.randamount || 0,
        invoiceData.lcnumber || '',
        invoiceData.transactiontype || 1,
        invoiceData.bankdetails || '',
        invoiceData.insurancedetails || '',
        invoiceData.grossweight || 0,
        invoiceData.netweight || 0,
        invoiceData.volume || 0,
        invoiceData.packagecount || 0,
        invoiceData.certificateoforigin || '',
        invoiceData.customsdeclaration || '',
        invoiceData.specialinstructions || '',
        invoiceData.additionaldetails || '',
        invoiceData.expectedstockstatus || 'planning'
      ];
    }

    const result = await pool.query(query, params);
    
    if (isUpdate) {
      console.log(`Updated invoice ${invoiceData.poinvoiceid}`);
      res.status(200).json({ 
        success: true,
        message: 'Invoice updated successfully'
      });
    } else {
      const invoiceId = result.rows[0].poinvoiceid;
      console.log(`Created invoice with ID: ${invoiceId}`);
      res.status(201).json({ 
        success: true,
        message: 'Invoice created successfully', 
        poinvoiceid: invoiceId 
      });
    }
    
  } catch (err) {
    console.error("Error with invoice:", err);
    res.status(500).json({ 
      success: false, 
      error: err.message 
    });
  }
});

// PUT - Update an invoice - CONVERTED
app.put('/api/po-invoices/:invoiceId', async (req, res) => {
  console.log("PUT /api/po-invoices/:invoiceId called, ID =", req.params.invoiceId);
  try {
    const { invoiceId } = req.params;
    const invoiceData = req.body;
    
    await ensurePOInvoiceTable();
    
    const query = `
      UPDATE poinvoice SET
        vendorref = $2,
        vendorid = $3,
        currency = $4,
        foreignvalue = $5,
        paymentterms = $6,
        apn = $7,
        incoterm = $8,
        hscode = $9,
        countryoforigin = $10,
        transportmode = $11,
        containertype = $12,
        containercount = $13,
        portofloading = $14,
        portofdischarge = $15,
        vesselname = $16,
        roe = $17,
        roedate = $18,
        randamount = $19,
        lcnumber = $20,
        transactiontype = $21,
        bankdetails = $22,
        insurancedetails = $23,
        grossweight = $24,
        netweight = $25,
        volume = $26,
        packagecount = $27,
        certificateoforigin = $28,
        customsdeclaration = $29,
        specialinstructions = $30,
        additionaldetails = $31,
        expectedstockstatus = $32,
        updatedat = NOW()
      WHERE poinvoiceid = $1
    `;

    await pool.query(query, [
      invoiceId,
      invoiceData.vendorref || '',
      invoiceData.vendorid ? parseInt(invoiceData.vendorid) : null,
      invoiceData.currency || 'USD',
      invoiceData.foreignvalue || 0,
      invoiceData.paymentterms || 'Net 30',
      invoiceData.apn || '',
      invoiceData.incoterm || '',
      invoiceData.hscode || '',
      invoiceData.countryoforigin || '',
      invoiceData.transportmode || '',
      invoiceData.containertype || '',
      invoiceData.containercount || 1,
      invoiceData.portofloading || '',
      invoiceData.portofdischarge || '',
      invoiceData.vesselname || '',
      invoiceData.roe || 1.0000,
      sanitizeDate(invoiceData.roedate),
      invoiceData.randamount || 0,
      invoiceData.lcnumber || '',
      invoiceData.transactiontype || 1,
      invoiceData.bankdetails || '',
      invoiceData.insurancedetails || '',
      invoiceData.grossweight || 0,
      invoiceData.netweight || 0,
      invoiceData.volume || 0,
      invoiceData.packagecount || 0,
      invoiceData.certificateoforigin || '',
      invoiceData.customsdeclaration || '',
      invoiceData.specialinstructions || '',
      invoiceData.additionaldetails || '',
      invoiceData.expectedstockstatus || 'planning'
    ]);

    console.log("Complete invoice updated successfully!");
    res.status(200).json({ success: true, message: 'Complete invoice updated successfully' });
  } catch (err) {
    console.error("Complete invoice update failed:", err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// DELETE - Delete an invoice - CONVERTED
app.delete('/api/po-invoices/:invoiceId', async (req, res) => {
  console.log("DELETE /api/po-invoices/:invoiceId called, ID =", req.params.invoiceId);
  try {
    const { invoiceId } = req.params;
    
    await ensurePOInvoiceTable();
    const query = `DELETE FROM poinvoice WHERE poinvoiceid = $1`;
    await pool.query(query, [invoiceId]);
    
    console.log("Po-invoice deleted successfully!");
    res.status(200).json({ success: true, message: 'Invoice deleted successfully' });
  } catch (err) {
    console.error("Po-invoice deletion failed:", err);
    res.status(500).json({ success: false, error: err.message });
  }
});

/* ---------------------------------------------------------------
   EXPECTED STOCK STATUS API ENDPOINTS - CONVERTED
---------------------------------------------------------------- */

// PUT - Update Expected Stock Status for an invoice - CONVERTED
app.put('/api/expected-stock-status/:invoiceId', async (req, res) => {
  console.log("PUT /api/expected-stock-status/:invoiceId called, ID =", req.params.invoiceId);
  console.log("Status update body:", req.body);
  
  try {
    const { invoiceId } = req.params;
    const { status } = req.body;
    
    // Validate status value
    const validStatuses = ['planning', 'confirmed', 'shipped', 'arrived', 'completed'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({
        success: false,
        error: `Invalid status. Must be one of: ${validStatuses.join(', ')}`
      });
    }
    
    await ensurePOInvoiceTable();
    
    const query = `
      UPDATE poinvoice 
      SET expectedstockstatus = $2,
          updatedat = NOW()
      WHERE poinvoiceid = $1
    `;
    
    const result = await pool.query(query, [invoiceId, status]);
    
    if (result.rowCount === 0) {
      return res.status(404).json({
        success: false,
        error: 'Invoice not found'
      });
    }
    
    console.log(`Updated ExpectedStockStatus to '${status}' for invoice ${invoiceId}`);
    
    res.status(200).json({
      success: true,
      message: `Status updated to '${status}' successfully`,
      invoiceId: invoiceId,
      newStatus: status
    });
    
  } catch (error) {
    console.error("Error updating expected stock status:", error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// GET - Get Expected Stock Status for an invoice - CONVERTED
app.get('/api/expected-stock-status/:invoiceId', async (req, res) => {
  console.log("GET /api/expected-stock-status/:invoiceId called, ID =", req.params.invoiceId);
  
  try {
    const { invoiceId } = req.params;
    
    await ensurePOInvoiceTable();
    
    const query = `
      SELECT expectedstockstatus, poinvoiceid, invoiceno, updatedat
      FROM poinvoice 
      WHERE poinvoiceid = $1
    `;
    
    const result = await pool.query(query, [invoiceId]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'Invoice not found'
      });
    }
    
    const invoice = result.rows[0];
    
    res.status(200).json({
      success: true,
      invoiceId: invoice.poinvoiceid,
      invoiceNo: invoice.invoiceno,
      status: invoice.expectedstockstatus || 'planning',
      lastUpdated: invoice.updatedat
    });
    
  } catch (error) {
    console.error("Error fetching expected stock status:", error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/* ---------------------------------------------------------------
   PO BOOKINGS API ENDPOINTS - CONVERTED TO POSTGRESQL
---------------------------------------------------------------- */

// Ensure POBooking table exists
async function ensurePOBookingTable() {
  try {
    const tableCheck = await pool.query(`
      SELECT COUNT(*) as count FROM information_schema.tables 
      WHERE table_schema = 'public' AND table_name = 'pobooking'
    `);
    
    if (parseInt(tableCheck.rows[0].count) === 0) {
      console.log("Creating POBooking table...");
      await pool.query(`
        CREATE TABLE pobooking (
          pobookingid SERIAL PRIMARY KEY,
          bookingreference VARCHAR(255) NOT NULL,
          bookingdate TIMESTAMP,
          loadtype VARCHAR(100),
          tptdetail1 VARCHAR(255),
          tptdetail2 VARCHAR(255),
          masterno VARCHAR(255),
          houseno VARCHAR(255),
          firstvessel VARCHAR(255),
          vesselcallsign VARCHAR(100),
          portofloading VARCHAR(255),
          destination VARCHAR(255),
          estimatedarrival TIMESTAMP,
          estimatedpickup TIMESTAMP,
          status INT DEFAULT 1,
          shipcarrier VARCHAR(255),
          createdat TIMESTAMP DEFAULT NOW(),
          updatedat TIMESTAMP DEFAULT NOW()
        )
      `);
      console.log("POBooking table created successfully!");
    } else {
      console.log("POBooking table already exists.");
    }
  } catch (err) {
    console.error("Error checking/creating POBooking table:", err);
  }
}

// Ensure POBookingLinks table exists
async function ensurePOBookingLinkTable() {
  try {
    const tableCheck = await pool.query(`
      SELECT COUNT(*) as count FROM information_schema.tables 
      WHERE table_schema = 'public' AND table_name = 'pobookinglink'
    `);
    
    if (parseInt(tableCheck.rows[0].count) === 0) {
      console.log("Creating POBookingLink table...");
      await pool.query(`
        CREATE TABLE pobookinglink (
          pobookinglinkid SERIAL PRIMARY KEY,
          orderid INT NOT NULL,
          pobookingid INT NOT NULL,
          bookedqty INT DEFAULT 1,
          createdat TIMESTAMP DEFAULT NOW(),
          CONSTRAINT fk_pobookinglink_order FOREIGN KEY (orderid) REFERENCES orders(orderid) ON DELETE CASCADE,
          CONSTRAINT fk_pobookinglink_booking FOREIGN KEY (pobookingid) REFERENCES pobooking(pobookingid) ON DELETE CASCADE
        )
      `);
      console.log("POBookingLink table created successfully!");
    } else {
      console.log("POBookingLink table already exists.");
    }
  } catch (err) {
    console.error("Error checking/creating POBookingLink table:", err);
  }
}

// GET bookings for a specific order - CONVERTED
app.get('/api/po-bookings', async (req, res) => {
  console.log("GET /api/po-bookings called with query:", req.query);
  try {
    await ensurePOBookingTable();
    await ensurePOBookingLinkTable();
    
    const { orderid } = req.query;
    
    if (orderid) {
      // Use LEFT JOIN to show ALL bookings, linked or not
      const query = `
        SELECT 
          b.pobookingid,
          b.bookingreference,
          b.bookingdate,
          b.loadtype,
          b.tptdetail1,
          b.tptdetail2,
          b.masterno,
          b.houseno,
          b.firstvessel,
          b.vesselcallsign,
          b.portofloading,
          b.destination,
          b.estimatedarrival,
          b.estimatedpickup,
          b.status,
          b.shipcarrier,
          COALESCE(bl.bookedqty, 0) as bookedqty,
          bl.pobookinglinkid,
          CASE WHEN bl.pobookinglinkid IS NOT NULL THEN 1 ELSE 0 END as islinked
        FROM pobooking b
        LEFT JOIN pobookinglink bl ON b.pobookingid = bl.pobookingid AND bl.orderid = $1
        ORDER BY b.bookingdate DESC
      `;
      
      const result = await pool.query(query, [orderid]);
      console.log(`${result.rows.length} bookings found for orderID=${orderid}`);

      // Map integer status back to strings for frontend
      const bookingsWithStringStatus = result.rows.map(booking => ({
        ...booking,
        Status: mapStatusToString(booking.status)
      }));

      res.status(200).json(bookingsWithStringStatus);
    } else {
      // Get all bookings (no order filter)
      const result = await pool.query(`
        SELECT * FROM pobooking 
        ORDER BY bookingdate DESC
      `);
      console.log("All bookings returned:", result.rows.length);
      
      // Map integer status back to strings for frontend
      const bookingsWithStringStatus = result.rows.map(booking => ({
        ...booking,
        Status: mapStatusToString(booking.status),
        IsLinked: 0,
        BookedQty: 0
      }));

      res.status(200).json(bookingsWithStringStatus);
    }
  } catch (err) {
    console.error("Error fetching bookings:", err);
    res.status(500).json({ error: err.message });
  }
});

// POST - Create new booking - CONVERTED
app.post('/api/po-bookings', async (req, res) => {
  console.log("POST /api/po-bookings called. Incoming body:", req.body);
  const {
    bookingreference, bookingdate, loadtype, tptdetail1, tptdetail2,
    masterno, houseno, firstvessel, vesselcallsign, portofloading,
    destination, estimatedarrival, estimatedpickup, status, shipcarrier,
    orderid
  } = req.body;
  
  try {
    await ensurePOBookingTable();
    await ensurePOBookingLinkTable();
    
    const query = `
      INSERT INTO pobooking (
        bookingreference, bookingdate, loadtype, tptdetail1, tptdetail2,
        masterno, houseno, firstvessel, vesselcallsign, portofloading,
        destination, estimatedarrival, estimatedpickup, status, shipcarrier,
        createdat, updatedat
      )
      VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, NOW(), NOW()
      )
      RETURNING pobookingid
    `;

    const result = await pool.query(query, [
      bookingreference,
      sanitizeDate(bookingdate),
      loadtype,
      tptdetail1,
      tptdetail2,
      masterno,
      houseno,
      firstvessel,
      vesselcallsign,
      portofloading,
      destination,
      sanitizeDate(estimatedarrival),
      sanitizeDate(estimatedpickup),
      mapStatusToInt(status),
      shipcarrier
    ]);

    const bookingId = result.rows[0].pobookingid;
    
    // Auto-link to order if orderid provided
    if (orderid) {
      const linkQuery = `
        INSERT INTO pobookinglink (orderid, pobookingid, bookedqty, createdat)
        VALUES ($1, $2, 1, NOW())
      `;
      await pool.query(linkQuery, [orderid, bookingId]);
      console.log(`Booking auto-linked to order ${orderid}`);
    }
    
    console.log("Booking created successfully with ID:", bookingId);
    res.status(201).json({ 
      success: true,
      message: 'Booking created successfully', 
      pobookingid: bookingId 
    });
  } catch (err) {
    console.error("Booking creation failed:", err);
    res.status(500).json({ error: err.message });
  }
});

// PUT - Update a booking - CONVERTED
app.put('/api/po-bookings/:bookingId', async (req, res) => {
  console.log("PUT /api/po-bookings/:bookingId called, ID =", req.params.bookingId);
  const { bookingId } = req.params;
  const {
    bookingreference, bookingdate, loadtype, tptdetail1, tptdetail2,
    masterno, houseno, firstvessel, vesselcallsign, portofloading,
    destination, estimatedarrival, estimatedpickup, status, shipcarrier
  } = req.body;

  try {
    await ensurePOBookingTable();
    
    const query = `
      UPDATE pobooking
      SET
        bookingreference = $2,
        bookingdate = $3,
        loadtype = $4,
        tptdetail1 = $5,
        tptdetail2 = $6,
        masterno = $7,
        houseno = $8,
        firstvessel = $9,
        vesselcallsign = $10,
        portofloading = $11,
        destination = $12,
        estimatedarrival = $13,
        estimatedpickup = $14,
        status = $15,
        shipcarrier = $16,
        updatedat = NOW()
      WHERE pobookingid = $1
    `;

    await pool.query(query, [
      bookingId,
      bookingreference,
      sanitizeDate(bookingdate),
      loadtype,
      tptdetail1,
      tptdetail2,
      masterno,
      houseno,
      firstvessel,
      vesselcallsign,
      portofloading,
      destination,
      sanitizeDate(estimatedarrival),
      sanitizeDate(estimatedpickup),
      mapStatusToInt(status),
      shipcarrier
    ]);

    console.log("Booking updated successfully!");
    res.status(200).json({ 
      success: true,
      message: 'Booking updated successfully' 
    });
  } catch (err) {
    console.error("Booking update failed:", err);
    res.status(500).json({ error: err.message });
  }
});

// DELETE - Delete a booking - CONVERTED
app.delete('/api/po-bookings/:bookingId', async (req, res) => {
  console.log("DELETE /api/po-bookings/:bookingId called, ID =", req.params.bookingId);
  const { bookingId } = req.params;
  
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await ensurePOBookingTable();
    
    // First delete any links to this booking
    await client.query(`DELETE FROM pobookinglink WHERE pobookingid = $1`, [bookingId]);
    
    // Then delete the booking itself
    const query = `DELETE FROM pobooking WHERE pobookingid = $1`;
    await client.query(query, [bookingId]);
    
    await client.query('COMMIT');
    console.log("Booking deleted successfully!");
    res.status(200).json({ 
      success: true,
      message: 'Booking deleted successfully' 
    });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error("Booking deletion failed:", err);
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

// POST - Link booking to order - CONVERTED
app.post('/api/po-booking-links', async (req, res) => {
  console.log("POST /api/po-booking-links called. Incoming body:", req.body);
  const { orderid, pobookingid, bookedqty } = req.body;
  
  try {
    await ensurePOBookingLinkTable();
    
    // Check if link already exists
    const existingLinkCheck = await pool.query(`
      SELECT COUNT(*) as count 
      FROM pobookinglink 
      WHERE orderid = $1 AND pobookingid = $2
    `, [orderid, pobookingid]);
    
    if (parseInt(existingLinkCheck.rows[0].count) > 0) {
      return res.status(400).json({ 
        error: 'This booking is already linked to this order' 
      });
    }
    
    const query = `
      INSERT INTO pobookinglink (orderid, pobookingid, bookedqty, createdat)
      VALUES ($1, $2, $3, NOW())
      RETURNING pobookinglinkid
    `;

    const result = await pool.query(query, [orderid, pobookingid, bookedqty || 1]);

    const linkId = result.rows[0].pobookinglinkid;
    
    console.log("Booking linked successfully with ID:", linkId);
    res.status(201).json({ 
      success: true,
      message: 'Booking linked successfully', 
      POBookingLinkID: linkId 
    });
  } catch (err) {
    console.error("Booking linking failed:", err);
    res.status(500).json({ error: err.message });
  }
});

// DELETE - Unlink booking from order - CONVERTED
app.delete('/api/po-booking-links/:linkId', async (req, res) => {
  console.log("DELETE /api/po-booking-links/:linkId called, ID =", req.params.linkId);
  const { linkId } = req.params;
  try {
    await ensurePOBookingLinkTable();
    
    const query = `DELETE FROM pobookinglink WHERE pobookinglinkid = $1`;
    await pool.query(query, [linkId]);
    
    console.log("Booking unlinked successfully!");
    res.status(200).json({ 
      success: true,
      message: 'Booking unlinked successfully' 
    });
  } catch (err) {
    console.error("Booking unlinking failed:", err);
    res.status(500).json({ error: err.message });
  }
});

// GET - Get all booking links for an order - CONVERTED
app.get('/api/po-booking-links', async (req, res) => {
  console.log("GET /api/po-booking-links called with query:", req.query);
  const { orderid } = req.query;
  
  try {
    await ensurePOBookingLinkTable();
    
    if (orderid) {
      const query = `
        SELECT bl.*, b.bookingreference, b.firstvessel, b.destination
        FROM pobookinglink bl
        INNER JOIN pobooking b ON bl.pobookingid = b.pobookingid
        WHERE bl.orderid = $1
      `;
      const result = await pool.query(query, [orderid]);
      
      console.log(`${result.rows.length} booking links found for orderid=${orderid}`);
      
      // Map integer status back to strings for frontend
      const bookingsWithStringStatus = result.rows.map(booking => ({
        ...booking,
        Status: mapStatusToString(booking.status || 1)
      }));

      res.status(200).json(bookingsWithStringStatus);
    } else {
      const result = await pool.query('SELECT * FROM pobookinglink');
      console.log("All booking links returned:", result.rows.length);
      
      const bookingsWithStringStatus = result.rows.map(booking => ({
        ...booking,
        Status: mapStatusToString(booking.status || 1)
      }));

      res.status(200).json(bookingsWithStringStatus);
    }
  } catch (err) {
    console.error("Error fetching booking links:", err);
    res.status(500).json({ error: err.message });
  }
});

/* ---------------------------------------------------------------
   FINAL INVOICE API ENDPOINTS - CONVERTED
---------------------------------------------------------------- */

// Ensure FinalInvoice table exists
async function ensureFinalInvoiceTable() {
  try {
    const tableCheck = await pool.query(`
      SELECT COUNT(*) as count FROM information_schema.tables 
      WHERE table_schema = 'public' AND table_name = 'finalinvoice'
    `);
    
    if (parseInt(tableCheck.rows[0].count) === 0) {
      console.log("Creating FinalInvoice table...");
      await pool.query(`
        CREATE TABLE finalinvoice (
          finalinvoiceid SERIAL PRIMARY KEY,
          orderid INT NOT NULL,
          invoicenumber VARCHAR(255) NOT NULL,
          invoicedate TIMESTAMP,
          duedate TIMESTAMP,
          customerreference VARCHAR(255),
          paymentterms VARCHAR(100),
          currency VARCHAR(10),
          subtotal DECIMAL(18,2),
          taxrate DECIMAL(5,4),
          taxamount DECIMAL(18,2),
          shippingcost DECIMAL(18,2),
          totalamount DECIMAL(18,2),
          companyname VARCHAR(255),
          companyaddress TEXT,
          companyemail VARCHAR(255),
          customername VARCHAR(255),
          customeraddress TEXT,
          customeremail VARCHAR(255),
          status VARCHAR(50) DEFAULT 'Draft',
          customfields TEXT,
          createdat TIMESTAMP DEFAULT NOW(),
          updatedat TIMESTAMP DEFAULT NOW(),
          CONSTRAINT fk_finalinvoice_order FOREIGN KEY (orderid) REFERENCES orders(orderid) ON DELETE CASCADE
        )
      `);
      console.log("FinalInvoice table created successfully!");
    } else {
      console.log("FinalInvoice table already exists.");
    }
  } catch (err) {
    console.error("Error checking/creating FinalInvoice table:", err);
  }
}

// GET final invoices for a specific order - CONVERTED
app.get('/api/final-invoices', async (req, res) => {
  console.log("GET /api/final-invoices called with query:", req.query);
  try {
    const { orderid } = req.query;
    
    if (!orderid) {
      console.log("orderid parameter missing");
      return res.status(400).json({ error: 'orderid is required' });
    }

    await ensureFinalInvoiceTable();
    const query = `SELECT * FROM finalinvoice WHERE orderid = $1 ORDER BY finalinvoiceid DESC`;
    const result = await pool.query(query, [orderid]);

    // Parse custom fields JSON for each invoice
    const invoices = result.rows.map(invoice => {
      try {
        if (invoice.customfields) {
          invoice.customfields = JSON.parse(invoice.customfields);
        }
      } catch (err) {
        console.warn("Warning: Could not parse CustomFields JSON:", err);
        invoice.customfields = {};
      }
      return invoice;
    });

    console.log(`${invoices.length} final invoices found for orderid=${orderid}`);
    res.status(200).json(invoices);
  } catch (err) {
    console.error("Error fetching final invoices:", err);
    res.status(500).json({ error: err.message });
  }
});

// Initialize database and tables for Section 4
(async function initDatabaseSection4() {
  try {
    console.log("Initializing Section 4 database tables...");
    await ensurePOInvoiceTable();
    await ensurePOBookingTable();
    await ensurePOBookingLinkTable(); 
    await ensureFinalInvoiceTable();
    console.log("Section 4 database tables verified.");
  } catch (err) {
    console.error("Failed to initialize Section 4 database:", err);
  }
})();

/* ---------------------------------------------------------------
   STOCK COLLECTION API ENDPOINTS - CONVERTED TO POSTGRESQL
---------------------------------------------------------------- */

// Ensure Stock Collection tables exist
async function ensureStockCollectionTables() {
  try {
    // Check if StockCollections table exists
    const stockCollectionsTableCheck = await pool.query(`
      SELECT COUNT(*) as count FROM information_schema.tables 
      WHERE table_schema = 'public' AND table_name = 'stockcollections'
    `);
    
    if (parseInt(stockCollectionsTableCheck.rows[0].count) === 0) {
      console.log("Creating StockCollections table...");
      await pool.query(`
        CREATE TABLE stockcollections (
          collectionid SERIAL PRIMARY KEY,
          drivername VARCHAR(100) NOT NULL,
          collectiondate DATE NOT NULL,
          status VARCHAR(50) NOT NULL DEFAULT 'Pending',
          createddate TIMESTAMP DEFAULT NOW(),
          updateddate TIMESTAMP DEFAULT NOW()
        )
      `);
      console.log("StockCollections table created successfully!");
    }

    // Check if CollectionItems table exists
    const collectionItemsTableCheck = await pool.query(`
      SELECT COUNT(*) as count FROM information_schema.tables 
      WHERE table_schema = 'public' AND table_name = 'collectionitems'
    `);
    
    if (parseInt(collectionItemsTableCheck.rows[0].count) === 0) {
      console.log("Creating CollectionItems table...");
      await pool.query(`
        CREATE TABLE collectionitems (
          itemid SERIAL PRIMARY KEY,
          collectionid INT NOT NULL,
          sku VARCHAR(50) NOT NULL,
          productname VARCHAR(200) NOT NULL,
          expectedquantity INT NOT NULL DEFAULT 0,
          collectedquantity INT NOT NULL DEFAULT 0,
          iscollected BOOLEAN NOT NULL DEFAULT FALSE,
          discrepancynote VARCHAR(500),
          createddate TIMESTAMP DEFAULT NOW(),
          updateddate TIMESTAMP DEFAULT NOW(),
          CONSTRAINT fk_collectionitems_collection FOREIGN KEY (collectionid) REFERENCES stockcollections(collectionid) ON DELETE CASCADE
        );
        
        CREATE INDEX IF NOT EXISTS idx_collectionitems_collectionid ON collectionitems(collectionid);
        CREATE INDEX IF NOT EXISTS idx_stockcollections_status ON stockcollections(status);
        CREATE INDEX IF NOT EXISTS idx_stockcollections_date ON stockcollections(collectiondate);
      `);
      console.log("CollectionItems table created successfully!");
    }
  } catch (err) {
    console.error("Error checking/creating Stock Collection tables:", err);
  }
}

// GET all stock collections - CONVERTED
app.get('/api/stock-collections', async (req, res) => {
  console.log("GET /api/stock-collections called");
  try {
    await ensureStockCollectionTables();
    
    const result = await pool.query(`
      SELECT * FROM stockcollections 
      ORDER BY collectiondate DESC, createddate DESC
    `);
    
    console.log(`${result.rows.length} stock collections found`);
    res.status(200).json(result.rows);
  } catch (err) {
    console.error("Error fetching stock collections:", err);
    res.status(500).json({ error: err.message });
  }
});

// GET specific stock collection by ID - CONVERTED
app.get('/api/stock-collections/:id', async (req, res) => {
  console.log("GET /api/stock-collections/:id called, ID =", req.params.id);
  const { id } = req.params;
  try {
    await ensureStockCollectionTables();
    
    const query = `SELECT * FROM stockcollections WHERE collectionid = $1`;
    const result = await pool.query(query, [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Stock collection not found' });
    }

    res.status(200).json(result.rows[0]);
  } catch (err) {
    console.error("Error fetching stock collection:", err);
    res.status(500).json({ error: err.message });
  }
});

// POST - Create new stock collection - CONVERTED
app.post('/api/stock-collections', async (req, res) => {
  console.log("POST /api/stock-collections called. Incoming body:", req.body);
  const { drivername, collectiondate, status } = req.body;
  
  if (!drivername || !collectiondate) {
    return res.status(400).json({ error: "DriverName and CollectionDate are required" });
  }
  
  try {
    await ensureStockCollectionTables();
    
    const query = `
      INSERT INTO stockcollections (drivername, collectiondate, status, createddate, updateddate)
      VALUES ($1, $2, $3, NOW(), NOW())
      RETURNING collectionid
    `;

    const result = await pool.query(query, [drivername, new Date(collectiondate), status || 'Pending']);
    const collectionId = result.rows[0].collectionid;
    
    console.log("Stock collection created successfully with ID:", collectionId);
    res.status(201).json({ 
      success: true,
      message: 'Stock collection created successfully', 
      CollectionID: collectionId 
    });
  } catch (err) {
    console.error("Stock collection creation failed:", err);
    res.status(500).json({ error: err.message });
  }
});

// PUT - Update stock collection - CONVERTED
app.put('/api/stock-collections/:id', async (req, res) => {
  console.log("PUT /api/stock-collections/:id called, ID =", req.params.id);
  const { id } = req.params;
  const { drivername, collectiondate, status } = req.body;

  try {
    await ensureStockCollectionTables();
    
    const query = `
      UPDATE stockcollections
      SET
        drivername = COALESCE($2, drivername),
        collectiondate = COALESCE($3, collectiondate),
        status = COALESCE($4, status),
        updateddate = NOW()
      WHERE collectionid = $1
    `;

    await pool.query(query, [id, drivername, collectiondate ? new Date(collectiondate) : null, status]);
    console.log("Stock collection updated successfully!");
    res.status(200).json({ 
      success: true,
      message: 'Stock collection updated successfully' 
    });
  } catch (err) {
    console.error("Stock collection update failed:", err);
    res.status(500).json({ error: err.message });
  }
});

// PUT - Bulk update collection items (Mark All/Clear All) - CONVERTED
app.put('/api/collection-items/bulk/:collectionId', async (req, res) => {
  console.log("PUT /api/collection-items/bulk/:collectionId called");
  const { collectionId } = req.params;
  const { action } = req.body; // 'mark_all' or 'clear_all'
  
  try {
    await ensureStockCollectionTables();
    
    let query;
    if (action === 'mark_all') {
      query = `
        UPDATE collectionitems 
        SET iscollected = TRUE, 
            collectedquantity = expectedquantity,
            discrepancynote = '',
            updateddate = NOW()
        WHERE collectionid = $1
      `;
    } else if (action === 'clear_all') {
      query = `
        UPDATE collectionitems 
        SET iscollected = FALSE, 
            collectedquantity = 0,
            discrepancynote = '',
            updateddate = NOW()
        WHERE collectionid = $1
      `;
    } else {
      return res.status(400).json({ error: "Invalid action. Use 'mark_all' or 'clear_all'" });
    }

    await pool.query(query, [collectionId]);
    
    console.log(`Bulk update (${action}) completed for collection ${collectionId}`);
    res.status(200).json({ 
      success: true,
      message: `Bulk update completed successfully` 
    });
  } catch (err) {
    console.error("Bulk update failed:", err);
    res.status(500).json({ error: err.message });
  }
});

// DELETE - Delete stock collection - CONVERTED
app.delete('/api/stock-collections/:id', async (req, res) => {
  console.log("DELETE /api/stock-collections/:id called, ID =", req.params.id);
  const { id } = req.params;
  try {
    await ensureStockCollectionTables();
    
    const query = `DELETE FROM stockcollections WHERE collectionid = $1`;
    await pool.query(query, [id]);
    
    console.log("Stock collection deleted successfully!");
    res.status(200).json({ 
      success: true,
      message: 'Stock collection deleted successfully' 
    });
  } catch (err) {
    console.error("Stock collection deletion failed:", err);
    res.status(500).json({ error: err.message });
  }
});

// GET collection items for a specific collection - CONVERTED
app.get('/api/collection-items/:collectionId', async (req, res) => {
  console.log("GET /api/collection-items/:collectionId called, ID =", req.params.collectionId);
  const { collectionId } = req.params;
  try {
    await ensureStockCollectionTables();
    
    const query = `SELECT * FROM collectionitems WHERE collectionid = $1 ORDER BY itemid`;
    const result = await pool.query(query, [collectionId]);

    console.log(`${result.rows.length} items found for collection ${collectionId}`);
    res.status(200).json(result.rows);
  } catch (err) {
    console.error("Error fetching collection items:", err);
    res.status(500).json({ error: err.message });
  }
});

// POST - Add item to collection - CONVERTED
app.post('/api/collection-items', async (req, res) => {
  console.log("POST /api/collection-items called. Incoming body:", req.body);
  const { collectionid, sku, productname, expectedquantity, collectedquantity, iscollected, discrepancynote } = req.body;
  
  if (!collectionid || !sku || !productname) {
    return res.status(400).json({ error: "CollectionID, SKU, and ProductName are required" });
  }
  
  try {
    await ensureStockCollectionTables();
    
    const query = `
      INSERT INTO collectionitems (
        collectionid, sku, productname, expectedquantity, 
        collectedquantity, iscollected, discrepancynote, createddate, updateddate
      )
      VALUES (
        $1, $2, $3, $4, $5, $6, $7, NOW(), NOW()
      )
      RETURNING itemid
    `;

    const result = await pool.query(query, [
      collectionid, sku, productname, expectedquantity || 0,
      collectedquantity || 0, iscollected || false, discrepancynote || null
    ]);

    const itemId = result.rows[0].itemid;
    
    console.log("Collection item created successfully with ID:", itemId);
    res.status(201).json({ 
      success: true,
      message: 'Collection item created successfully', 
      ItemID: itemId 
    });
  } catch (err) {
    console.error("Collection item creation failed:", err);
    res.status(500).json({ error: err.message });
  }
});

// PUT - Update collection item - CONVERTED
app.put('/api/collection-items/:id', async (req, res) => {
  console.log("PUT /api/collection-items/:id called, ID =", req.params.id);
  const { id } = req.params;
  const { iscollected, collectedquantity, discrepancynote } = req.body;

  try {
    await ensureStockCollectionTables();
    
    const query = `
      UPDATE collectionitems
      SET
        iscollected = $2,
        collectedquantity = $3,
        discrepancynote = $4,
        updateddate = NOW()
      WHERE itemid = $1
    `;

    await pool.query(query, [id, iscollected, collectedquantity, discrepancynote || '']);

    console.log("Collection item updated successfully!");
    res.status(200).json({ 
      success: true,
      message: 'Collection item updated successfully' 
    });
  } catch (err) {
    console.error("Collection item update failed:", err);
    res.status(500).json({ error: err.message });
  }
});

// DELETE - Delete collection item - CONVERTED
app.delete('/api/collection-items/:id', async (req, res) => {
  console.log("DELETE /api/collection-items/:id called, ID =", req.params.id);
  const { id } = req.params;
  try {
    await ensureStockCollectionTables();
    
    const query = `DELETE FROM collectionitems WHERE itemid = $1`;
    await pool.query(query, [id]);
    
    console.log("Collection item deleted successfully!");
    res.status(200).json({ 
      success: true,
      message: 'Collection item deleted successfully' 
    });
  } catch (err) {
    console.error("Collection item deletion failed:", err);
    res.status(500).json({ error: err.message });
  }
});

/* ---------------------------------------------------------------
   COMMUNICATIONS HUB DATABASE TABLES & ENDPOINTS - CONVERTED
---------------------------------------------------------------- */

// Ensure Communications table exists (standalone function)
async function ensureCommunicationsTable() {
  try {
    const tableCheck = await pool.query(`
      SELECT COUNT(*) as count FROM information_schema.tables 
      WHERE table_schema = 'public' AND table_name = 'communications'
    `);
    
    if (parseInt(tableCheck.rows[0].count) === 0) {
      console.log("Creating Communications table...");
      await pool.query(`
        CREATE TABLE communications (
          communicationid SERIAL PRIMARY KEY,
          orderid INT NOT NULL,
          userid INT NOT NULL,
          messagetype VARCHAR(50) NOT NULL,
          subject VARCHAR(255),
          messagebody TEXT,
          attachmentpath VARCHAR(500),
          isread BOOLEAN DEFAULT FALSE,
          priority VARCHAR(20) DEFAULT 'normal',
          createdat TIMESTAMP DEFAULT NOW(),
          updatedat TIMESTAMP DEFAULT NOW(),
          CONSTRAINT fk_communications_order FOREIGN KEY (orderid) REFERENCES orders(orderid) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_communications_orderid ON communications(orderid);
        CREATE INDEX IF NOT EXISTS idx_communications_userid ON communications(userid);
      `);
    }
  } catch (err) {
    console.error("Error checking/creating Communications table:", err);
  }
}

// Ensure Communications Hub tables exist
async function ensureCommunicationsHubTables() {
  try {
    // Create Milestones table
    const milestonesTableCheck = await pool.query(`
      SELECT COUNT(*) as count FROM information_schema.tables 
      WHERE table_schema = 'public' AND table_name = 'milestones'
    `);
    
    if (parseInt(milestonesTableCheck.rows[0].count) === 0) {
      console.log("Creating Milestones table...");
      await pool.query(`
        CREATE TABLE milestones (
          milestoneid SERIAL PRIMARY KEY,
          orderid INT NOT NULL,
          userid INT NOT NULL,
          milestonetype VARCHAR(50) NOT NULL,
          status VARCHAR(50) NOT NULL DEFAULT 'pending',
          title VARCHAR(255) NOT NULL,
          description TEXT,
          duedate TIMESTAMP,
          completeddate TIMESTAMP,
          completedbyuserid INT,
          priority VARCHAR(20) DEFAULT 'medium',
          isvisible BOOLEAN DEFAULT TRUE,
          createdat TIMESTAMP DEFAULT NOW(),
          updatedat TIMESTAMP DEFAULT NOW(),
          CONSTRAINT fk_milestones_order FOREIGN KEY (orderid) REFERENCES orders(orderid) ON DELETE CASCADE
        );
        
        CREATE INDEX IF NOT EXISTS idx_milestones_orderid ON milestones(orderid);
        CREATE INDEX IF NOT EXISTS idx_milestones_status ON milestones(status);
        CREATE INDEX IF NOT EXISTS idx_milestones_type ON milestones(milestonetype);
      `);
      console.log("Milestones table created successfully!");
    }

    // Create Communications table
    const communicationsTableCheck = await pool.query(`
      SELECT COUNT(*) as count FROM information_schema.tables 
      WHERE table_schema = 'public' AND table_name = 'communications'
    `);
    
    if (parseInt(communicationsTableCheck.rows[0].count) === 0) {
      console.log("Creating Communications table...");
      await pool.query(`
        CREATE TABLE communications (
          communicationid SERIAL PRIMARY KEY,
          orderid INT NOT NULL,
          userid INT NOT NULL,
          messagetype VARCHAR(50) NOT NULL,
          subject VARCHAR(255),
          messagebody TEXT,
          attachmentpath VARCHAR(500),
          isread BOOLEAN DEFAULT FALSE,
          priority VARCHAR(20) DEFAULT 'normal',
          createdat TIMESTAMP DEFAULT NOW(),
          updatedat TIMESTAMP DEFAULT NOW(),
          CONSTRAINT fk_communications_order FOREIGN KEY (orderid) REFERENCES orders(orderid) ON DELETE CASCADE
        );
        
        CREATE INDEX IF NOT EXISTS idx_communications_orderid ON communications(orderid);
        CREATE INDEX IF NOT EXISTS idx_communications_userid ON communications(userid);
        CREATE INDEX IF NOT EXISTS idx_communications_type ON communications(messagetype);
        CREATE INDEX IF NOT EXISTS idx_communications_createdat ON communications(createdat);
      `);
      console.log("Communications table created successfully!");
    }

    // Create Documents table
    const documentsTableCheck = await pool.query(`
      SELECT COUNT(*) as count FROM information_schema.tables 
      WHERE table_schema = 'public' AND table_name = 'documents'
    `);
    
    if (parseInt(documentsTableCheck.rows[0].count) === 0) {
      console.log("Creating Documents table...");
      await pool.query(`
        CREATE TABLE documents (
          documentid SERIAL PRIMARY KEY,
          orderid INT NOT NULL,
          uploadedbyuserid INT NOT NULL,
          filename VARCHAR(255) NOT NULL,
          originalfilename VARCHAR(255) NOT NULL,
          filepath VARCHAR(500) NOT NULL,
          filesize BIGINT,
          mimetype VARCHAR(100),
          documenttype VARCHAR(50),
          description VARCHAR(500),
          ispublic BOOLEAN DEFAULT TRUE,
          createdat TIMESTAMP DEFAULT NOW(),
          updatedat TIMESTAMP DEFAULT NOW(),
          CONSTRAINT fk_documents_order FOREIGN KEY (orderid) REFERENCES orders(orderid) ON DELETE CASCADE
        );
        
        CREATE INDEX IF NOT EXISTS idx_documents_orderid ON documents(orderid);
        CREATE INDEX IF NOT EXISTS idx_documents_type ON documents(documenttype);
        CREATE INDEX IF NOT EXISTS idx_documents_createdat ON documents(createdat);
      `);
      console.log("Documents table created successfully!");
    }

  } catch (err) {
    console.error("Error checking/creating Communications Hub tables:", err);
  }
}

/* ---------------------------------------------------------------
   Initialize Section 5 Database Tables
---------------------------------------------------------------- */
(async function initDatabaseSection5() {
  try {
    console.log("Initializing Section 5 database tables...");
    await ensureStockCollectionTables();
    await ensureCommunicationsHubTables();
    console.log("Section 5 database tables verified.");
  } catch (err) {
    console.error("Failed to initialize Section 5 database:", err);
  }
})();

/* ---------------------------------------------------------------
   MILESTONE MANAGEMENT ENDPOINTS - CONVERTED
---------------------------------------------------------------- */

// GET milestones for an order - CONVERTED
app.get('/api/milestones', async (req, res) => {
  console.log("GET /api/milestones called with query:", req.query);
  const { orderid } = req.query;
  
  try {
    await ensureCommunicationsHubTables();
    
    if (!orderid) {
      return res.status(400).json({ error: 'OrderID is required' });
    }
    
    const query = `
      SELECT m.*, u.username as completedbyusername
      FROM milestones m
      LEFT JOIN users u ON m.completedbyuserid = u.userid
      WHERE m.orderid = $1 AND m.isvisible = TRUE
      ORDER BY m.createdat ASC
    `;
    
    const result = await pool.query(query, [orderid]);
    
    console.log(`${result.rows.length} milestones found for order ${orderid}`);
    res.status(200).json(result.rows);
    
  } catch (err) {
    console.error("Error fetching milestones:", err);
    res.status(500).json({ error: err.message });
  }
});

// POST - Create new milestone - CONVERTED
app.post('/api/milestones', async (req, res) => {
  console.log("POST /api/milestones called. Incoming body:", req.body);
  const {
    orderid, userid, milestonetype, title, description, 
    duedate, priority = 'medium'
  } = req.body;
  
  if (!orderid || !userid || !milestonetype || !title) {
    return res.status(400).json({ 
      error: "orderid, userid, milestonetype, and title are required" 
    });
  }
  
  try {
    await ensureCommunicationsHubTables();
    
    const query = `
      INSERT INTO milestones (
        orderid, userid, milestonetype, status, title, description,
        duedate, priority, createdat, updatedat
      )
      VALUES (
        $1, $2, $3, 'pending', $4, $5, $6, $7, NOW(), NOW()
      )
      RETURNING milestoneid
    `;
    
    const result = await pool.query(query, [
      orderid, userid, milestonetype, title, description,
      duedate ? new Date(duedate) : null, priority
    ]);

    const milestoneId = result.rows[0].milestoneid;
    
    console.log("Milestone created successfully with ID:", milestoneId);
    res.status(201).json({
      success: true,
      message: 'Milestone created successfully',
      MilestoneID: milestoneId
    });
    
  } catch (err) {
    console.error("Milestone creation failed:", err);
    res.status(500).json({ error: err.message });
  }
});

// PUT - Update milestone status - CONVERTED
app.put('/api/milestones/:milestoneId', async (req, res) => {
  console.log("PUT /api/milestones/:milestoneId called, ID =", req.params.milestoneId);
  const { milestoneId } = req.params;
  const { status, completedbyuserid } = req.body;
  
  try {
    await ensureCommunicationsHubTables();
    
    let query;
    let params;
    
    if (status === 'completed') {
      query = `
        UPDATE milestones
        SET
          status = $2,
          completeddate = NOW(),
          completedbyuserid = $3,
          updatedat = NOW()
        WHERE milestoneid = $1
      `;
      params = [milestoneId, status, completedbyuserid || null];
    } else {
      query = `
        UPDATE milestones
        SET
          status = $2,
          completeddate = NULL,
          completedbyuserid = $3,
          updatedat = NOW()
        WHERE milestoneid = $1
      `;
      params = [milestoneId, status, completedbyuserid || null];
    }
    
    await pool.query(query, params);
    
    console.log(`Milestone ${milestoneId} updated to status: ${status}`);
    res.status(200).json({
      success: true,
      message: 'Milestone updated successfully'
    });
    
  } catch (err) {
    console.error("Milestone update failed:", err);
    res.status(500).json({ error: err.message });
  }
});

/* ---------------------------------------------------------------
   COMMUNICATION ENDPOINTS - CONVERTED
---------------------------------------------------------------- */

// GET communications for an order - CONVERTED
app.get('/api/communications', async (req, res) => {
  console.log("GET /api/communications called with query:", req.query);
  const { orderid } = req.query;
  
  try {
    await ensureCommunicationsHubTables();
    
    if (!orderid) {
      return res.status(400).json({ error: 'OrderID is required' });
    }
    
    const query = `
      SELECT DISTINCT c.*, 
             u.username,
             u.firstname, 
             u.lastname, 
             (SELECT ucr2."Role" 
              FROM usercompanyroles ucr2 
              WHERE ucr2.userid = u.userid LIMIT 1) as role,
             (SELECT comp2.companyname 
              FROM usercompanyroles ucr3
              INNER JOIN companies comp2 ON ucr3.companyid = comp2.companyid
              WHERE ucr3.userid = u.userid LIMIT 1) as companyname
      FROM communications c
      LEFT JOIN users u ON c.userid = u.userid
      WHERE c.orderid = $1
      ORDER BY c.createdat ASC
    `;
        
    const result = await pool.query(query, [orderid]);
    
    console.log(`${result.rows.length} communications found for order ${orderid}`);
    res.status(200).json(result.rows);
    
  } catch (err) {
    console.error("Error fetching communications:", err);
    res.status(500).json({ error: err.message });
  }
});

// POST - Send message/communication - CONVERTED
app.post('/api/communications', async (req, res) => {
  console.log("POST /api/communications called. Incoming body:", req.body);
  const { orderid, userid, messagetype, subject, messagebody, priority = 'normal' } = req.body;
  
  if (!orderid || !userid || !messagetype || !messagebody) {
    return res.status(400).json({
      error: "orderid, userid, messagetype, and messagebody are required"
    });
  }
  
  try {
    await ensureCommunicationsHubTables();
    
    const query = `
      INSERT INTO communications (
        orderid, userid, messagetype, subject, messagebody, 
        priority, createdat, updatedat
      )
      VALUES (
        $1, $2, $3, $4, $5, $6, NOW(), NOW()
      )
      RETURNING communicationid
    `;
    
    const result = await pool.query(query, [orderid, userid, messagetype, subject || null, messagebody, priority]);
    const communicationId = result.rows[0].communicationid;
    
    console.log("Communication created successfully with ID:", communicationId);
    res.status(201).json({
      success: true,
      message: 'Message sent successfully',
      CommunicationID: communicationId
    });
    
  } catch (err) {
    console.error("Communication creation failed:", err);
    res.status(500).json({ error: err.message });
  }
});

// POST /api/communications/typing endpoint (for typing indicators)
app.post('/api/communications/typing', (req, res) => {
  console.log("POST /api/communications/typing called");
  console.log("Typing data:", req.body);
  
  // This is a placeholder for real-time typing indicators
  // In a production app, you'd broadcast this to other users via WebSocket
  res.status(200).json({ 
    success: true, 
    message: 'Typing indicator received' 
  });
});

// POST /api/communications/external-notify endpoint (for external notifications)
app.post('/api/communications/external-notify', (req, res) => {
  console.log("POST /api/communications/external-notify called");
  console.log("Notification data:", req.body);
  
  // This is a placeholder for external notifications (email, SMS, etc.)
  // In production, you'd integrate with email/SMS services here
  const { orderid, userid, notificationType, message } = req.body;
  
  res.status(200).json({ 
    success: true, 
    message: 'External notification processed',
    orderid: orderid,
    notificationType: notificationType
  });
});

/* ---------------------------------------------------------------
   MILESTONE ACTION ENDPOINTS - CONVERTED
---------------------------------------------------------------- */

// POST - Confirm Order - CONVERTED
app.post('/api/milestones/confirm-order', async (req, res) => {
  console.log("POST /api/milestones/confirm-order called");
  const { orderid, userid } = req.body;
  
  if (!orderid || !userid) {
    return res.status(400).json({ error: "orderid and userid are required" });
  }
  
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await ensureCommunicationsHubTables();
    
    // Check if order is already confirmed
    const existingCheck = await client.query(`
      SELECT COUNT(*) as count FROM milestones 
      WHERE orderid = $1 AND milestonetype = 'order_confirmed'
    `, [orderid]);
    
    if (parseInt(existingCheck.rows[0].count) > 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: "Order already confirmed" });
    }
    
    // Create milestone for order confirmation
    const milestoneQuery = `
      INSERT INTO milestones (
        orderid, userid, milestonetype, status, title, description,
        completeddate, completedbyuserid, createdat, updatedat
      )
      VALUES (
        $1, $2, 'order_confirmed', 'completed', 
        'Order Confirmed', 'Purchase order confirmed by exporter',
        NOW(), $2, NOW(), NOW()
      )
      RETURNING milestoneid
    `;
    
    const milestoneResult = await client.query(milestoneQuery, [orderid, userid]);
    const milestoneId = milestoneResult.rows[0].milestoneid;
    
    // Update order status
    const orderQuery = `UPDATE orders SET orderstatus = 'Confirmed' WHERE orderid = $1`;
    await client.query(orderQuery, [orderid]);
    
    // Create communication record
    const commQuery = `
      INSERT INTO communications (
        orderid, userid, messagetype, subject, messagebody, createdat, updatedat
      )
      VALUES (
        $1, $2, 'milestone_update', 'Order Confirmed',
        'Purchase order has been confirmed by the exporter. Production can begin.', NOW(), NOW()
      )
    `;
    
    await client.query(commQuery, [orderid, userid]);
    
    await client.query('COMMIT');
    console.log(`Order ${orderid} confirmed successfully`);
    res.status(200).json({
      success: true,
      message: 'Order confirmed successfully',
      milestoneId: milestoneId
    });
    
  } catch (err) {
    await client.query('ROLLBACK');
    console.error("Order confirmation failed:", err);
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

// POST - Ready to Ship (Step 3 - Exporter milestone) - CONVERTED
app.post('/api/milestones/ready-to-ship', async (req, res) => {
  console.log("POST /api/milestones/ready-to-ship called");
  const { orderid, userid } = req.body;
  
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    
    // Check if order is confirmed first
    const confirmCheck = await client.query(`
      SELECT COUNT(*) as count FROM milestones 
      WHERE orderid = $1 AND milestonetype = 'order_confirmed' AND status = 'completed'
    `, [orderid]);
    
    if (parseInt(confirmCheck.rows[0].count) === 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ 
        error: "Order must be confirmed before marking as ready to ship" 
      });
    }
    
    // Update all invoices to "confirmed" status (production complete)
    const invoiceQuery = `
      UPDATE poinvoice 
      SET expectedstockstatus = 'confirmed', updatedat = NOW() 
      WHERE orderid = $1
    `;
    await client.query(invoiceQuery, [orderid]);
    
    // Create milestone
    const milestoneQuery = `
      INSERT INTO milestones (
        orderid, userid, milestonetype, status, title, description,
        completeddate, completedbyuserid, createdat, updatedat
      )
      VALUES (
        $1, $2, 'ready_to_ship', 'completed',
        'Ready to Ship', 'Production complete. Goods prepared and ready for dispatch.',
        NOW(), $2, NOW(), NOW()
      )
    `;
    await client.query(milestoneQuery, [orderid, userid]);
    
    // Create communication
    const commQuery = `
      INSERT INTO communications (
        orderid, userid, messagetype, subject, messagebody, createdat, updatedat
      )
      VALUES (
        $1, $2, 'milestone_update', 'Goods Ready to Ship',
        'Production is complete. All goods are prepared and ready for collection/dispatch.', NOW(), NOW()
      )
    `;
    await client.query(commQuery, [orderid, userid]);
    
    await client.query('COMMIT');
    res.status(200).json({
      success: true,
      message: 'Goods marked as ready to ship'
    });
    
  } catch (err) {
    await client.query('ROLLBACK');
    console.error("Ready to ship failed:", err);
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

// POST - Goods Shipped (Step 4 - Exporter milestone) - CONVERTED
app.post('/api/milestones/goods-shipped', async (req, res) => {
  console.log("POST /api/milestones/goods-shipped called");
  const { orderid, userid } = req.body;
  
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    
    // Check if goods are ready to ship first
    const readyCheck = await client.query(`
      SELECT COUNT(*) as count FROM milestones 
      WHERE orderid = $1 AND milestonetype = 'ready_to_ship' AND status = 'completed'
    `, [orderid]);
    
    if (parseInt(readyCheck.rows[0].count) === 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ 
        error: "Goods must be marked as 'Ready to Ship' before shipping" 
      });
    }
    
    // Update all invoices to "shipped" status
    const invoiceQuery = `
      UPDATE poinvoice 
      SET expectedstockstatus = 'shipped', updatedat = NOW() 
      WHERE orderid = $1
    `;
    await client.query(invoiceQuery, [orderid]);
    
    // Create milestone
    const milestoneQuery = `
      INSERT INTO milestones (
        orderid, userid, milestonetype, status, title, description,
        completeddate, completedbyuserid, createdat, updatedat
      )
      VALUES (
        $1, $2, 'goods_shipped', 'completed',
        'Goods Shipped', 'Goods have been dispatched and are now in transit.',
        NOW(), $2, NOW(), NOW()
      )
    `;
    await client.query(milestoneQuery, [orderid, userid]);
    
    // Update order status to shipped
    const orderQuery = `UPDATE orders SET orderstatus = 'Shipped' WHERE orderid = $1`;
    await client.query(orderQuery, [orderid]);
    
    // Create communication
    const commQuery = `
      INSERT INTO communications (
        orderid, userid, messagetype, subject, messagebody, createdat, updatedat
      )
      VALUES (
        $1, $2, 'milestone_update', 'Goods Shipped',
        'Goods have been dispatched from origin and are now in transit to destination.', NOW(), NOW()
      )
    `;
    await client.query(commQuery, [orderid, userid]);
    
    await client.query('COMMIT');
    res.status(200).json({
      success: true,
      message: 'Goods marked as shipped'
    });
    
  } catch (err) {
    await client.query('ROLLBACK');
    console.error("Goods shipped failed:", err);
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

// POST - Goods Arrived (Step 5 - Importer milestone) - CONVERTED
app.post('/api/milestones/goods-arrived', async (req, res) => {
  console.log("POST /api/milestones/goods-arrived called");
  const { orderid, userid } = req.body;
  
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    
    // Check if goods have been shipped first
    const shippedCheck = await client.query(`
      SELECT COUNT(*) as count FROM milestones 
      WHERE orderid = $1 AND milestonetype = 'goods_shipped' AND status = 'completed'
    `, [orderid]);
    
    if (parseInt(shippedCheck.rows[0].count) === 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ 
        error: "Goods must be shipped before they can arrive" 
      });
    }
    
    // Update all invoices to "arrived" status
    const invoiceQuery = `
      UPDATE poinvoice 
      SET expectedstockstatus = 'arrived', updatedat = NOW() 
      WHERE orderid = $1
    `;
    await client.query(invoiceQuery, [orderid]);
    
    // Create milestone
    const milestoneQuery = `
      INSERT INTO milestones (
        orderid, userid, milestonetype, status, title, description,
        completeddate, completedbyuserid, createdat, updatedat
      )
      VALUES (
        $1, $2, 'goods_arrived', 'completed',
        'Goods Arrived', 'Shipment has arrived at destination and is ready for collection.',
        NOW(), $2, NOW(), NOW()
      )
    `;
    await client.query(milestoneQuery, [orderid, userid]);
    
    // Create communication
    const commQuery = `
      INSERT INTO communications (
        orderid, userid, messagetype, subject, messagebody, createdat, updatedat
      )
      VALUES (
        $1, $2, 'milestone_update', 'Goods Arrived at Destination',
        'Shipment has arrived at destination port/facility and is ready for collection or final delivery.', NOW(), NOW()
      )
    `;
    await client.query(commQuery, [orderid, userid]);
    
    await client.query('COMMIT');
    res.status(200).json({
      success: true,
      message: 'Goods marked as arrived'
    });
    
  } catch (err) {
    await client.query('ROLLBACK');
    console.error("Goods arrived failed:", err);
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

// POST - Goods Received (Step 6 - Importer milestone) - CONVERTED
app.post('/api/milestones/goods-received', async (req, res) => {
  console.log("POST /api/milestones/goods-received called");
  const { orderid, userid } = req.body;
  
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    
    // Check if goods have arrived first
    const arrivedCheck = await client.query(`
      SELECT COUNT(*) as count FROM milestones 
      WHERE orderid = $1 AND milestonetype = 'goods_arrived' AND status = 'completed'
    `, [orderid]);
    
    if (parseInt(arrivedCheck.rows[0].count) === 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ 
        error: "Goods must arrive before they can be received" 
      });
    }
    
    // Update all invoices to "completed" status
    const invoiceQuery = `
      UPDATE poinvoice 
      SET expectedstockstatus = 'completed', updatedat = NOW() 
      WHERE orderid = $1
    `;
    await client.query(invoiceQuery, [orderid]);
    
    // Create milestone
    const milestoneQuery = `
      INSERT INTO milestones (
        orderid, userid, milestonetype, status, title, description,
        completeddate, completedbyuserid, createdat, updatedat
      )
      VALUES (
        $1, $2, 'goods_received', 'completed',
        'Goods Received & Verified', 'Final delivery completed and goods verified by importer.',
        NOW(), $2, NOW(), NOW()
      )
    `;
    await client.query(milestoneQuery, [orderid, userid]);
    
    // Update order status to completed
    const orderQuery = `UPDATE orders SET orderstatus = 'Completed' WHERE orderid = $1`;
    await client.query(orderQuery, [orderid]);
    
    // Create communication
    const commQuery = `
      INSERT INTO communications (
        orderid, userid, messagetype, subject, messagebody, createdat, updatedat
      )
      VALUES (
        $1, $2, 'milestone_update', 'Order Complete',
        'Goods have been received, verified, and the order is now complete. Thank you for your business!', NOW(), NOW()
      )
    `;
    await client.query(commQuery, [orderid, userid]);
    
    await client.query('COMMIT');
    res.status(200).json({
      success: true,
      message: 'Goods received and order completed'
    });
    
  } catch (err) {
    await client.query('ROLLBACK');
    console.error("Goods received failed:", err);
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

/* ---------------------------------------------------------------
   DOCUMENT UPLOAD ENDPOINTS - CONVERTED
---------------------------------------------------------------- */

// Create uploads directory if it doesn't exist
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadsDir);
  },
  filename: function (req, file, cb) {
    // Generate unique filename: timestamp-originalname
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const extension = path.extname(file.originalname);
    const baseName = path.basename(file.originalname, extension);
    cb(null, `${baseName}-${uniqueSuffix}${extension}`);
  }
});

// File filter for security
const fileFilter = (req, file, cb) => {
  // Allow specific file types
  const allowedTypes = [
    'application/json',           // VPL files
    'application/pdf',            // Documents, invoices
    'image/jpeg',                // Photos
    'image/png',                 // Photos
    'image/gif',                 // Photos
    'application/msword',        // Word documents
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document', // Word .docx
    'application/vnd.ms-excel',   // Excel files
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', // Excel .xlsx
    'text/csv',                  // CSV files
    'text/plain'                 // Text files
  ];

  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error(`File type ${file.mimetype} not allowed. Allowed types: PDF, Images, Office documents, JSON, CSV, TXT`), false);
  }
};

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB limit
    files: 10 // Maximum 10 files per upload
  },
  fileFilter: fileFilter
});

// POST - Upload documents - CONVERTED
app.post('/api/upload-document', upload.array('files', 10), async (req, res) => {
  console.log("POST /api/upload-document called");
  console.log("Files received:", req.files?.length || 0);
  console.log("Body:", req.body);

  try {
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ 
        success: false, 
        error: 'No files uploaded' 
      });
    }

    const { orderid, userid, documenttype, description } = req.body;

    if (!orderid || !userid) {
      // Clean up uploaded files if validation fails
      req.files.forEach(file => {
        if (fs.existsSync(file.path)) {
          fs.unlinkSync(file.path);
        }
      });
      
      return res.status(400).json({ 
        success: false, 
        error: 'OrderID and UserID are required' 
      });
    }

    await ensureCommunicationsHubTables();

    const uploadedFiles = [];

    // Process each uploaded file
    for (const file of req.files) {
      const query = `
        INSERT INTO documents (
          orderid, uploadedbyuserid, filename, originalfilename, 
          filepath, filesize, mimetype, documenttype, description,
          ispublic, createdat, updatedat
        )
        VALUES (
          $1, $2, $3, $4, $5, $6, $7, $8, $9, TRUE, NOW(), NOW()
        )
        RETURNING documentid
      `;

      const result = await pool.query(query, [
        orderid, userid, file.filename, file.originalname, file.path,
        file.size, file.mimetype, documentType || 'other', description || ''
      ]);

      const documentId = result.rows[0].documentid;

      uploadedFiles.push({
        documentId,
        originalName: file.originalname,
        fileName: file.filename,
        size: file.size,
        type: file.mimetype
      });

      console.log(`Document uploaded: ${file.originalname} (ID: ${documentId})`);
    }

    // Create a communication record for the upload
    const commQuery = `
      INSERT INTO communications (
        orderid, userid, messagetype, subject, messagebody, createdat, updatedat
      )
      VALUES (
        $1, $2, 'document', 'Document Upload', $3, NOW(), NOW()
      )
    `;

    const messageBody = `Uploaded ${uploadedFiles.length} document(s): ${uploadedFiles.map(f => f.originalName).join(', ')}`;
    await pool.query(commQuery, [orderid, userid, messageBody]);

    res.status(200).json({
      success: true,
      message: `${uploadedFiles.length} file(s) uploaded successfully`,
      files: uploadedFiles
    });

  } catch (err) {
    console.error("Document upload failed:", err);
    
    // Clean up uploaded files on error
    if (req.files) {
      req.files.forEach(file => {
        if (fs.existsSync(file.path)) {
          fs.unlinkSync(file.path);
        }
      });
    }

    res.status(500).json({ 
      success: false, 
      error: err.message 
    });
  }
});

// GET - Fetch documents for an order - CONVERTED
app.get('/api/documents', async (req, res) => {
  console.log("GET /api/documents called with query:", req.query);
  const { orderid } = req.query;

  try {
    if (!orderid) {
      return res.status(400).json({ error: 'OrderID is required' });
    }

    await ensureCommunicationsHubTables();

    const query = `
      SELECT DISTINCT d.*, 
             u.username as uploadedbyusername,
             (SELECT comp.companyname 
              FROM usercompanyroles ucr2
              INNER JOIN companies comp ON ucr2.companyid = comp.companyid
              WHERE ucr2.userid = u.userid LIMIT 1) as uploadedbycompany
      FROM documents d
      LEFT JOIN users u ON d.uploadedbyuserid = u.userid
      WHERE d.orderid = $1 AND d.ispublic = TRUE
      ORDER BY d.createdat DESC
    `;

    const result = await pool.query(query, [orderid]);

    console.log(`${result.rows.length} documents found for order ${orderid}`);
    res.status(200).json(result.rows);

  } catch (err) {
    console.error("Error fetching documents:", err);
    res.status(500).json({ error: err.message });
  }
});

// GET - Download a document - CONVERTED
app.get('/api/documents/download/:documentId', async (req, res) => {
  console.log("GET /api/documents/download/:documentId called");
  const { documentId } = req.params;

  try {
    await ensureCommunicationsHubTables();

    const query = `
      SELECT * FROM documents 
      WHERE documentid = $1 AND ispublic = TRUE
    `;

    const result = await pool.query(query, [documentId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Document not found' });
    }

    const document = result.rows[0];
    const filePath = document.filepath;

    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'File not found on server' });
    }

    // Set appropriate headers
    res.setHeader('Content-Disposition', `attachment; filename="${document.originalfilename}"`);
    res.setHeader('Content-Type', document.mimetype);

    // Stream the file
    const fileStream = fs.createReadStream(filePath);
    fileStream.pipe(res);

    console.log(`Document downloaded: ${document.originalfilename}`);

  } catch (err) {
    console.error("Error downloading document:", err);
    res.status(500).json({ error: err.message });
  }
});

// DELETE - Delete a document - CONVERTED
app.delete('/api/documents/:documentId', async (req, res) => {
  console.log("DELETE /api/documents/:documentId called");
  const { documentId } = req.params;

  try {
    await ensureCommunicationsHubTables();

    // First, get the document info
    const getQuery = `SELECT * FROM documents WHERE documentid = $1`;
    const result = await pool.query(getQuery, [documentId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Document not found' });
    }

    const document = result.rows[0];

    // Delete from database
    const deleteQuery = `DELETE FROM documents WHERE documentid = $1`;
    await pool.query(deleteQuery, [documentId]);

    // Delete physical file
    if (fs.existsSync(document.filepath)) {
      fs.unlinkSync(document.filepath);
      console.log(`Physical file deleted: ${document.filepath}`);
    }

    res.status(200).json({
      success: true,
      message: 'Document deleted successfully'
    });

    console.log(`Document deleted: ${document.originalfilename} (ID: ${documentId})`);

  } catch (err) {
    console.error("Error deleting document:", err);
    res.status(500).json({ error: err.message });
  }
});

/* ---------------------------------------------------------------
   VIRTUAL PACKING LIST GENERATION & VERIFICATION - CONVERTED
---------------------------------------------------------------- */

// Ensure VirtualPackingListReferences table exists
async function ensureVPLReferencesTable() {
  try {
    const tableCheck = await pool.query(`
      SELECT COUNT(*) as count FROM information_schema.tables 
      WHERE table_schema = 'public' AND table_name = 'virtualpackinglistreferences'
    `);
    
    if (parseInt(tableCheck.rows[0].count) === 0) {
      console.log("Creating VirtualPackingListReferences table...");
      await pool.query(`
        CREATE TABLE virtualpackinglistreferences (
          referenceid SERIAL PRIMARY KEY,
          referencenumber VARCHAR(100) NOT NULL UNIQUE,
          baseinvoicenumber VARCHAR(50) NOT NULL,
          securitytoken VARCHAR(10) NOT NULL,
          exportorderid INT NOT NULL,
          importorderid INT NULL,
          exportercompany VARCHAR(200) NULL,
          consigneecompany VARCHAR(200) NULL,
          status VARCHAR(50) NOT NULL DEFAULT 'Generated',
          createdat TIMESTAMP NOT NULL DEFAULT NOW(),
          linkedat TIMESTAMP NULL,
          completedat TIMESTAMP NULL,
          totallines INT DEFAULT 0,
          totalquantity INT DEFAULT 0,
          totalvalue DECIMAL(18,2) DEFAULT 0.00,
          estimatedshipdate DATE NULL,
          actualshipdate DATE NULL,
          securityhash VARCHAR(128) NULL,
          jsondata TEXT NULL,
          CONSTRAINT fk_vplref_exportorder FOREIGN KEY (exportorderid) 
              REFERENCES orders(orderid) ON DELETE NO ACTION,
          CONSTRAINT fk_vplref_importorder FOREIGN KEY (importorderid) 
              REFERENCES orders(orderid) ON DELETE NO ACTION
        );
        
        CREATE INDEX IF NOT EXISTS idx_vplref_referencenumber 
            ON virtualpackinglistreferences (referencenumber);
        CREATE INDEX IF NOT EXISTS idx_vplref_exportorderid 
            ON virtualpackinglistreferences (exportorderid);
        CREATE INDEX IF NOT EXISTS idx_vplref_status 
            ON virtualpackinglistreferences (status);
      `);
      console.log("VirtualPackingListReferences table created successfully!");
    } else {
      console.log("VirtualPackingListReferences table already exists.");
    }
  } catch (err) {
    console.error("Error checking/creating VirtualPackingListReferences table:", err);
  }
}

// POST - Generate Virtual Packing List with security hash - CONVERTED
app.post('/api/generate-vpl', async (req, res) => {
  console.log("POST /api/generate-vpl called");
  try {
    const {
      referenceNumber,
      orderData,
      lineItems,
      exporterCompany,
      consigneeCompany,
      estimatedShipDate,
      portOfLoading,
      portOfDischarge,
      incoterm,
      specialInstructions
    } = req.body;

    // Create the VPL data structure
    const vplData = {
      referenceNumber,
      dateGenerated: new Date().toISOString(),
      estimatedShipDate,
      
      // Company Information
      exporter: {
        company: exporterCompany,
        contact: orderData?.supplierContact || '',
      },
      
      consignee: {
        company: consigneeCompany,
        contact: orderData?.buyerContact || '',
      },
      
      // Shipping Information  
      shipping: {
        portOfLoading,
        portOfDischarge,
        incoterm,
        specialInstructions: specialInstructions || ''
      },
      
      // Order Information
      orderDetails: {
        orderNumber: orderData?.orderNumber,
        orderType: 'Export',
        currency: orderData?.currency || 'USD'
      },
      
      // Line Items (The critical part for import parsing)
      lineItems: lineItems.map((line, index) => {
        // Handle weight array data
        const weight = Array.isArray(line.Weight || line.weight) ? 
          (line.Weight || line.weight).find(val => val !== null && val !== undefined) || 0 : 
          (line.Weight || line.weight);

        // Handle volume array data  
        const volume = Array.isArray(line.Volume || line.volume) ? 
          (line.Volume || line.volume).find(val => val !== null && val !== undefined) || 0 : 
          (line.Volume || line.volume);

        return {
          lineNumber: index + 1,
          partNumber: line.PartNumber || '',
          description: line.Description || '',
          quantity: line.Quantity || 0,
          unitOfMeasure: line.UOM || 'UNIT',
          unitPrice: line.UnitPrice || 0,
          lineTotal: (line.Quantity || 0) * (line.UnitPrice || 0),
          lineStatus: line.LineStatus || 'Pending',
          weight: parseFloat(weight) || 0,
          volume: parseFloat(volume) || 0
        };
      }),
      
      // Summary
      summary: {
        totalLines: lineItems.length,
        totalQuantity: lineItems.reduce((sum, line) => sum + (line.Quantity || 0), 0),
        totalValue: lineItems.reduce((sum, line) => sum + ((line.Quantity || 0) * (line.UnitPrice || 0)), 0),
        totalWeight: lineItems.reduce((sum, line) => {
          const weight = Array.isArray(line.Weight || line.weight) ? 
            (line.Weight || line.weight)[1] || (line.Weight || line.weight)[0] : 
            (line.Weight || line.weight);
          return sum + (parseFloat(weight) || 0);
        }, 0),
        totalVolume: lineItems.reduce((sum, line) => {
          const volume = Array.isArray(line.Volume || line.volume) ? 
            (line.Volume || line.volume)[1] || (line.Volume || line.volume)[0] : 
            (line.Volume || line.volume);
          return sum + (parseFloat(volume) || 0);
        }, 0)
      }
    };

    // Generate security hash
    const securityHash = generateSecurityHash(vplData);
    
    // Add security hash to the data
    const secureVplData = {
      ...vplData,
      securityHash
    };

    // Store VPL reference in database
    await ensureVPLReferencesTable();
    
    const insertQuery = `
      INSERT INTO virtualpackinglistreferences (
        referencenumber, baseinvoicenumber, securitytoken, exportorderid,
        exportercompany, consigneecompany, status, totallines, totalquantity,
        totalvalue, estimatedshipdate, securityhash, jsondata, createdat
      )
      VALUES (
        $1, $2, $3, $4, $5, $6, 'Generated', $7, $8, $9, $10, $11, $12, NOW()
      )
      RETURNING referenceid
    `;

    const securityToken = Math.random().toString(36).substring(2, 12).toUpperCase();
    
    await pool.query(insertQuery, [
      referenceNumber,
      orderData?.invoiceNumber || 'INV-' + Date.now(),
      securityToken,
      orderData?.Orderid || null,
      exporterCompany,
      consigneeCompany,
      vplData.summary.totalLines,
      vplData.summary.totalQuantity,
      vplData.summary.totalValue,
      estimatedShipDate ? new Date(estimatedShipDate) : null,
      securityHash,
      JSON.stringify(secureVplData)
    ]);

    console.log('VPL generated with security hash');
    res.status(200).json({
      success: true,
      vplData: secureVplData,
      message: 'Virtual Packing List generated successfully with security verification'
    });

  } catch (error) {
    console.error('Error generating VPL:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// POST - Verify uploaded VPL security - CONVERTED
app.post('/api/verify-vpl', async (req, res) => {
  console.log("POST /api/verify-vpl called");
  try {
    const { vplData } = req.body;

    if (!vplData || !vplData.securityHash) {
      return res.status(400).json({
        success: false,
        error: 'Invalid VPL data - missing security hash'
      });
    }

    // Verify security hash
    const verification = verifySecurityHash(vplData);

    if (verification.isValid) {
      console.log('VPL security verification passed');
      res.status(200).json({
        success: true,
        isValid: true,
        message: 'VPL is authentic and has not been tampered with',
        vplData
      });
    } else {
      console.log('VPL security verification failed');
      res.status(400).json({
        success: false,
        isValid: false,
        error: 'VPL has been tampered with or is invalid',
        details: verification.error || 'Security hash mismatch'
      });
    }

  } catch (error) {
    console.error('Error verifying VPL:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/* ---------------------------------------------------------------
   USER ORDERS API FOR GLOBAL CHAT SYSTEM - CONVERTED
---------------------------------------------------------------- */

// GET /api/user-orders - Get all orders for a user (for global chat) - CONVERTED
app.get('/api/user-orders', authenticateToken, async (req, res) => {
  try {
    const { userID } = req.query;
    
    // Use the authenticated user's ID if userID not provided in query
    const targetUserID = userID || req.user.userId;
    
    const query = `
      SELECT 
        po.orderid,
        po.ordernumber,
        po.goodsdescription,
        po.orderstatus
      FROM orders po
      WHERE po.userid = $1 
      ORDER BY po.orderid DESC
    `;
    
    const result = await pool.query(query, [targetUserID]);
    
    console.log(`${result.rows.length} orders found for user ${targetUserID}`);
    res.json(result.rows || []);
  } catch (error) {
    console.error('Error fetching user orders:', error);
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

// GET /api/communications/unread-count - Get unread message count for an order/user - CONVERTED
app.get('/api/communications/unread-count', async (req, res) => {
  try {
    const { orderid, userid } = req.query;
    
    // For now, return 0 as we haven't implemented read/unread tracking yet
    res.json({ count: 0 });
  } catch (error) {
    console.error('Error fetching unread count:', error);
    res.json({ count: 0 });
  }
});

/* ---------------------------------------------------------------
   Initialize Section 7 Database Tables
---------------------------------------------------------------- */
(async function initDatabaseSection7() {
  try {
    console.log("Initializing Section 7 database tables...");
    await ensureVPLReferencesTable();
    console.log("Section 7 database tables verified.");
  } catch (err) {
    console.error("Failed to initialize Section 7 database:", err);
  }
})();

/* ---------------------------------------------------------------
   Invoice Generation Endpoint - CONVERTED
   - Retrieves order data
   - Constructs invoiceData with logo path
   - Generates PDF using Puppeteer & Handlebars
   - Returns PDF as binary
---------------------------------------------------------------- */
app.get('/invoice/:id', async (req, res) => {
  const orderId = req.params.id;
  console.log("GET /invoice/:id called, ID =", orderId);

  try {
    // Retrieve order from database - CONVERTED
    const query = 'SELECT * FROM orders WHERE orderid = $1';
    const result = await pool.query(query, [orderid]);

    if (result.rows.length === 0) {
      console.log("No order found with ID =", orderId);
      return res.status(404).json({ message: 'Order not found' });
    }

    const order = result.rows[0];

    const invoiceData = {
      companyLogo: 'http://localhost:3000/i.XBeta.png',
      companyName: 'Your Company Name',
      companyEmail: 'info@yourcompany.com',
      companyPhone: '123-456-7890',
      companyVatNo: 'VAT123456',
      companyRegNo: 'REG123456',

      invoiceNumber: order.ordernumber || `INV-${order.orderid}`,
      invoiceDate: new Date().toISOString().split('T')[0],
      agentRef: order.agentref || '',
      paymentTerms: order.paymentterms || 'Net 30',
      paymentDate: '2023-12-01',

      accNo: 'ACC-12345',
      customerName: order.exporter || 'Unknown Exporter',
      consigneeName: order.shipmentconsignee || 'Unknown Consignee',

      bankDetails: 'Your Bank Details Here',
      branchCode: 'BR123',
      bankAccNo: 'BA123456',

      // For lineItems, if you have order lines, you would query them here
      lineItems: [
        { description: 'Item 1', quantity: 2, unitPrice: 100, vatCode: 'S', lineTotal: 200 },
      ],

      subTotal: 200,
      vatTotal: 30,
      grandTotal: 230,
      companyWebsite: 'https://www.yourcompany.com'
    };

    // Generate the PDF
    const pdfBuffer = await generateInvoicePDF(invoiceData);
    console.log("PDF generated, size =", pdfBuffer.length, "bytes");

    // Set headers and send PDF
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename=invoice_${orderId}.pdf`);
    res.send(pdfBuffer);

  } catch (err) {
    console.error("Error generating invoice:", err);
    res.status(500).json({ error: err.message });
  }
});

/* ---------------------------------------------------------------
   FINAL INVOICE ENDPOINTS COMPLETION - CONVERTED
---------------------------------------------------------------- */

// POST - Create a new final invoice - CONVERTED
app.post('/api/final-invoices', async (req, res) => {
  console.log("POST /api/final-invoices called. Incoming body:", req.body);
  const invoiceData = req.body;
  
  try {
    await ensureFinalInvoiceTable();
    
    const query = `
      INSERT INTO finalinvoice (
        orderid, invoicenumber, invoicedate, duedate, customerreference,
        paymentterms, currency, subtotal, taxrate, taxamount, shippingcost,
        totalamount, companyname, companyaddress, companyemail, customername,
        customeraddress, customeremail, status, customfields, createdat, updatedat
      )
      VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, NOW(), NOW()
      )
      RETURNING finalinvoiceid
    `;

    const result = await pool.query(query, [
      invoiceData.purchaseorderid,
      invoiceData.invoicenumber,
      invoiceData.invoicedate ? new Date(invoiceData.invoicedate) : null,
      invoiceData.duedate ? new Date(invoiceData.duedate) : null,
      invoiceData.customerreference,
      invoiceData.paymentterms,
      invoiceData.currency,
      invoiceData.subtotal,
      invoiceData.taxrate,
      invoiceData.taxamount,
      invoiceData.shippingcost,
      invoiceData.totalamount,
      invoiceData.companyname,
      invoiceData.companyaddress,
      invoiceData.companyemail,
      invoiceData.customername,
      invoiceData.customeraddress,
      invoiceData.customeremail,
      invoiceData.status || 'Draft',
      JSON.stringify(invoiceData.customfields || {})
    ]);

    const invoiceId = result.rows[0].finalinvoiceid;
    
    console.log("Final invoice created successfully with ID:", invoiceId);
    res.status(201).json({ 
      success: true,
      message: 'Final invoice created successfully', 
      FinalInvoiceID: invoiceId 
    });
  } catch (err) {
    console.error("Final invoice creation failed:", err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// PUT - Update a final invoice - CONVERTED
app.put('/api/final-invoices/:invoiceId', async (req, res) => {
  console.log("PUT /api/final-invoices/:invoiceId called, ID =", req.params.invoiceId);
  const { invoiceId } = req.params;
  const invoiceData = req.body;

  try {
    await ensureFinalInvoiceTable();
    
    const query = `
      UPDATE finalinvoice
      SET
        invoicenumber = $2,
        invoicedate = $3,
        duedate = $4,
        customerreference = $5,
        paymentterms = $6,
        currency = $7,
        subtotal = $8,
        taxrate = $9,
        taxamount = $10,
        shippingcost = $11,
        totalamount = $12,
        companyname = $13,
        companyaddress = $14,
        companyemail = $15,
        customername = $16,
        customeraddress = $17,
        customeremail = $18,
        status = $19,
        customfields = $20,
        updatedat = NOW()
      WHERE finalinvoiceid = $1
    `;

    await pool.query(query, [
      invoiceId,
      invoiceData.invoicenumber,
      invoiceData.invoicedate ? new Date(invoiceData.invoicedate) : null,
      invoiceData.duedate ? new Date(invoiceData.duedate) : null,
      invoiceData.customerreference,
      invoiceData.paymentterms,
      invoiceData.currency,
      invoiceData.subtotal,
      invoiceData.taxrate,
      invoiceData.taxamount,
      invoiceData.shippingcost,
      invoiceData.totalamount,
      invoiceData.companyname,
      invoiceData.companyaddress,
      invoiceData.companyemail,
      invoiceData.customername,
      invoiceData.customeraddress,
      invoiceData.customeremail,
      invoiceData.status,
      JSON.stringify(invoiceData.customfields || {})
    ]);

    console.log("Final invoice updated successfully!");
    res.status(200).json({ 
      success: true,
      message: 'Final invoice updated successfully' 
    });
  } catch (err) {
    console.error("Final invoice update failed:", err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// DELETE - Delete a final invoice - CONVERTED
app.delete('/api/final-invoices/:invoiceId', async (req, res) => {
  console.log("DELETE /api/final-invoices/:invoiceId called, ID =", req.params.invoiceId);
  const { invoiceId } = req.params;
  try {
    await ensureFinalInvoiceTable();
    
    const query = `DELETE FROM finalinvoice WHERE finalinvoiceid = $1`;
    await pool.query(query, [invoiceId]);
    
    console.log("Final invoice deleted successfully!");
    res.status(200).json({ 
      success: true,
      message: 'Final invoice deleted successfully' 
    });
  } catch (err) {
    console.error("Final invoice deletion failed:", err);
    res.status(500).json({ success: false, error: err.message });
  }
});

/* ---------------------------------------------------------------
   ADDITIONAL UTILITY ENDPOINTS - CONVERTED
---------------------------------------------------------------- */



// Endpoint to get all subdivisions (combined UN/LOCODE entries)
app.get('/api/unlocodes', (req, res) => {
  res.json(subdivisionsData);
});

// Endpoint for real-time search on subdivisions using query parameter "q"
app.get('/api/search-unlocodes', (req, res) => {
  const query = req.query.q;
  if (!query) {
    return res.status(400).json({ error: 'Query parameter "q" is required.' });
  }
  const lowerQuery = query.toLowerCase();
  
  // Filter entries that include the query in any of the three columns
  let results = subdivisionsData.filter(entry => {
    const c1 = (entry.column1 || '').toLowerCase();
    const c2 = (entry.column2 || '').toLowerCase();
    const c3 = (entry.column3 || '').toLowerCase();
    return c1.includes(lowerQuery) || c2.includes(lowerQuery) || c3.includes(lowerQuery);
  });

  // Rank the results
  results.sort((a, b) => rankEntry(b, lowerQuery) - rankEntry(a, lowerQuery));
  res.json(results);
});

function rankEntry(entry, lowerQuery) {
  const c1 = (entry.column1 || '').toLowerCase();
  const c2 = (entry.column2 || '').toLowerCase();
  const c3 = (entry.column3 || '').toLowerCase();
  let score = 0;
  
  // Give a high score if the country code starts with the query
  if (c1.startsWith(lowerQuery)) {
    score += 5;
  } else if (c1.includes(lowerQuery)) {
    score += 1;
  }
  
  // If the numeric or other code starts with query, add a medium boost
  if (c2.startsWith(lowerQuery)) {
    score += 4;
  } else if (c2.includes(lowerQuery)) {
    score += 1;
  }
  
  // For city/subdivision name
  if (c3.startsWith(lowerQuery)) {
    score += 3;
  } else if (c3.includes(lowerQuery)) {
    score += 1;
  }
  
  return score;
}

/* ---------------------------------------------------------------
   FINAL INITIALIZATION AND SERVER STARTUP - CONVERTED
---------------------------------------------------------------- */

// Initialize all database tables for the complete application
(async function initCompleteDatabase() {
  try {
    const poolConnection = await connectDB();
    if (poolConnection) {
      console.log("=== INITIALIZING COMPLETE DATABASE SCHEMA ===");
      
      // Core tables
      await ensureProductsTable();
      await ensureOrderLinesTable();
      await ensureVirtualShelvesTable();
      await ensureClientsTable();
      await ensureSuppliersTable();
      
      // Reporting and preferences
      await ensureReportsTable();
      await ensureUserPreferencesTable();
      await ensureSavedImportsTable();
      await ensureProductGroupsTable();
      
      // Invoice and booking system
      await ensurePOInvoiceTable();
      await ensurePOBookingTable();
      await ensurePOBookingLinkTable(); 
      await ensureFinalInvoiceTable();
      
      // Stock management
      await ensureStockCollectionTables();
      
      // Communications hub
      await ensureCommunicationsTable();
      await ensureCommunicationsHubTables();
      
      // VPL system
      await ensureVPLReferencesTable();
      
      console.log("=== ALL DATABASE TABLES VERIFIED AND READY ===");
      
    } else {
      console.log("Database connection failed - some features may not work.");
    }
  } catch (err) {
    console.error("Failed to initialize complete database:", err);
  }
})();

/* ---------------------------------------------------------------
   Serve production build from dist folder one level up
---------------------------------------------------------------- */
const distPath = path.join(__dirname, '..', 'dist');
app.use(express.static(distPath));

app.get('*', (req, res) => {
  res.sendFile(path.join(distPath, 'index.html'));
});

/* ---------------------------------------------------------------
   Start the server on all network interfaces - CONVERTED
---------------------------------------------------------------- */
app.listen(port, '0.0.0.0', () => {
  console.log(`=== BLUE MOON POSTGRESQL SERVER STARTED ===`);
  console.log(`Server running on http://localhost:${port}`);
  console.log(`Network access available on all interfaces`);
  console.log(`Database: PostgreSQL (bluemoondb)`);
  console.log(`Total endpoints: 50+ fully converted from SQL Server`);
  console.log(`Ready for production use!`);
  console.log(`=============================================`);
});