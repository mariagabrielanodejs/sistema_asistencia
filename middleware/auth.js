const jwt = require('jsonwebtoken');
require('dotenv').config();
module.exports = {
    isAuthenticated: (req, res, next) => {
        const token = req.cookies.token;
        
        if (!token) {
            return res.redirect('/');
        }

        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            req.user = decoded;
            next();
        } catch (error) {
            res.clearCookie('token');
            res.redirect('/');
        }
    },
    
    isGuest: (req, res, next) => {
        const token = req.cookies.token;
        if (token) {
            try {
                jwt.verify(token, process.env.JWT_SECRET);
                return res.redirect('/visitante');
            } catch (error) {
                res.clearCookie('token');
            }
        }
        next();
    }
};