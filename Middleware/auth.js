const jwt = require('jsonwebtoken');

// JWT Authentication Middleware
const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) {
      return res.status(401).json({ error: 'Access token required' });
    }

    // Verify JWT token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Get user details from database
    const pool = req.app.locals.dbPool;
    const userQuery = `
      SELECT u.userid, u.username, u.email, u.firstname, u.lastname,
             c.companyid, c.companyname, c.companytype,
             ucr."Role",
             p.permissionname
      FROM users u
      LEFT JOIN usercompanyroles ucr ON u.userid = ucr.userid
      LEFT JOIN companies c ON ucr.companyid = c.companyid
      LEFT JOIN userpermissions up ON u.userid = up.userid AND c.companyid = up.companyid
      LEFT JOIN permissions p ON up.permissionid = p.permissionid
      WHERE u.userid = $1 AND u.isactive = true
    `;

    const result = await pool.query(userQuery, [decoded.userId]);

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid token - user not found' });
    }

    // Structure user data
    const userData = result.rows[0];
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

    // Add user to request object
    req.user = user;
    next();

  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ error: 'Invalid token' });
    }
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expired' });
    }
    
    console.error('Authentication middleware error:', error);
    return res.status(500).json({ error: 'Authentication failed' });
  }
};

// Permission check middleware
const requirePermission = (permission) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    if (!req.user.permissions.includes(permission)) {
      return res.status(403).json({ 
        error: 'Insufficient permissions',
        required: permission,
        userPermissions: req.user.permissions
      });
    }

    next();
  };
};

// Company access check middleware
const requireCompanyAccess = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const companyId = req.params.companyId || req.query.companyId || req.body.companyId;
  
  if (companyId) {
    const hasAccess = req.user.companies.some(company => 
      company.companyId === parseInt(companyId)
    );

    if (!hasAccess) {
      return res.status(403).json({ 
        error: 'Access denied to this company',
        requestedCompany: companyId,
        userCompanies: req.user.companies.map(c => c.companyId)
      });
    }
  }

  next();
};

module.exports = {
  authenticateToken,
  requirePermission,
  requireCompanyAccess
};