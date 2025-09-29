const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const { authenticateToken } = require('../middleware/auth');

const router = express.Router();
console.log('JWT_SECRET loaded:', process.env.JWT_SECRET ? 'YES' : 'NO');
console.log('JWT_EXPIRES_IN loaded:', process.env.JWT_EXPIRES_IN);

// Generate JWT token
const generateToken = (userId, companies, permissions) => {
  return jwt.sign(
    { 
      userId, 
      companies: companies.map(c => c.companyId),
      permissions 
    },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN }
  );
};

// User Login
router.post('/login', [
  body('username').trim().escape(),
  body('password').notEmpty()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, password } = req.body;

    // Get user with companies and permissions - FIXED for PostgreSQL
    const pool = req.app.locals.dbPool;
    const userQuery = `
    SELECT u.userid, u.username, u.email, u.passwordhash, u.firstname, u.lastname,
           c.companyid, c.companyname, c.companytype,
           ucr."Role",
           p.permissionname
    FROM users u
    LEFT JOIN usercompanyroles ucr ON u.userid = ucr.userid
    LEFT JOIN companies c ON ucr.companyid = c.companyid
    LEFT JOIN userpermissions up ON u.userid = up.userid AND c.companyid = up.companyid
    LEFT JOIN permissions p ON up.permissionid = p.permissionid
    WHERE (u.username = $1 OR u.email = $1) AND u.isactive = true
  `;

    const result = await pool.query(userQuery, [username]);

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const userData = result.rows[0];

    // Verify password
    const validPassword = await bcrypt.compare(password, userData.passwordhash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Update last login
    await pool.query('UPDATE users SET lastlogin = NOW() WHERE userid = $1', [userData.userid]);

    // Structure user data
    const user = {
      userId: userData.userid,
      username: userData.username,
      email: userData.email,
      firstName: userData.firstname,
      lastName: userData.lastname,
      companies: [],
      permissions: []
    };

    // Group companies and permissions
    const companiesMap = new Map();
    result.rows.forEach(row => {
      if (row.companyid && !companiesMap.has(row.companyid)) {
        companiesMap.set(row.companyid, {
          companyId: row.companyid,
          companyName: row.companyname,
          companyType: row.companytype,
          role: row.Role
        });
      }
      if (row.permissionname && !user.permissions.includes(row.permissionname)) {
        user.permissions.push(row.permissionname);
      }
    });

    user.companies = Array.from(companiesMap.values());

    // Generate JWT token
    const token = generateToken(user.userId, user.companies, user.permissions);

    res.json({
      message: 'Login successful',
      token,
      user
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Get current user info
router.get('/me', authenticateToken, (req, res) => {
  res.json({
    user: req.user
  });
});

// User Registration
router.post('/register', [
  body('username').isLength({ min: 3 }).trim().escape(),
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 6 }),
  body('firstName').optional().trim().escape(),
  body('lastName').optional().trim().escape(),
  body('companyId').isInt()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, email, password, firstName, lastName, companyId, role = 'Read-Only User' } = req.body;

    // Check if user already exists
    const pool = req.app.locals.dbPool;
    const existingUser = await pool.query(
      'SELECT userid FROM users WHERE username = $1 OR email = $2', 
      [username, email]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'Username or email already exists' });
    }

    // Hash password
    const saltRounds = 12;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // Create user
    const result = await pool.query(`
      INSERT INTO users (username, email, passwordhash, firstname, lastname, isactive, createdat)
      VALUES ($1, $2, $3, $4, $5, true, NOW())
      RETURNING userid
    `, [username, email, passwordHash, firstName || '', lastName || '']);

    const userId = result.rows[0].userid;

    // Assign user to company with role
    await pool.query(`
      INSERT INTO usercompanyroles (userid, companyid, "Role", assigneddate)
      VALUES ($1, $2, $3, NOW())
    `, [userId, companyId, role]);

    res.status(201).json({
      message: 'User registered successfully',
      userId: userId
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

module.exports = router;