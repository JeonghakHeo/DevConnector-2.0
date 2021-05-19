const jwt = require('jsonwebtoken');
const config = require('config');

module.exports = function (req, res, next) {
  // Get token from header
  const token = req.header('x-auth-token');

  // Check if no token
  if (!token) {
    return res.status(401).json({ msg: 'No token, authorization denide' }); // 401 means not authorized
  }

  // Verify token
  try {
    //              jwt.verify(token, secretOrPublicKey, [options, callback])
    const decoded = jwt.verify(token, config.get('jwtSecret'));

    req.user = decoded.user;
    // console.log(req.user, decoded); <- check for auth.js 
    // decoded = user: { id: '5fa09b24af87fd1d36cc00b8' },
    //                   iat: 1604360996,
    //                   exp: 1604720996 
    //                 }
    next();
  }
  catch (err) {
    res.status(401).json({ msg: 'token is not valid' })
  }
};