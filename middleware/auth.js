// Description: Middlewares de autenticación
module.exports = {
    isAuthenticated: (req, res, next) => {
        if (req.session && req.session.userId) {
            return next();
        }
        res.redirect('/')
    },
    
    isGuest: (req, res, next) => {
        if (!(req.session && req.session.userId)) {
            return next();
        }
        res.redirect('/visitante');
    }
};