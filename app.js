const express = require('express');
const app = express();

const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const randtoken = require('rand-token');

const passport = require('passport');
const { Strategy: JwtStrategy, ExtractJwt } = require('passport-jwt');

const refreshTokens = {};
const SECRET = "sauce";

const options = {   
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: SECRET
};

passport.use(new JwtStrategy(options, (jwtPayload, done) => 
{
    const expirationDate = new Date(jwtPayload.exp * 1000);
    if (new Date() >= expirationDate) {
        return done(null, false);
    }

    const user = jwtPayload;
    done(null, user);
}));


app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));
app.use(passport.initialize());

app.post('/login', (req, res, next) => 
{
    const { username, password } = req.body;
    
    const accessToken = generateAccessToken(username, getRole(username));    
    const refreshToken = randtoken.uid(42);

    refreshTokens[refreshToken] = username;

    res.json({accessToken, refreshToken});
});

function generateAccessToken(username, role, expiresInSeconds = 60)
{
    const user = {
        username,
        role
    };

    const accessToken = jwt.sign(user, SECRET, { expiresIn: expiresInSeconds });
    
    return accessToken;
}


function getRole(username)
{
    switch (username) {
        case 'linus':
            return 'admin';
        default:
            return 'user';        
    }
}


app.post('/token', (req, res) => 
{
    const { username, refreshToken } = req.body;
    
    if (refreshToken in refreshTokens && refreshTokens[refreshToken] === username) {        
        const accessToken = generateAccessToken(username, getRole(username));
        res.json({accessToken});
    }
    else {
        res.sendStatus(401);
    }
});

app.delete('/token/:refreshToken', (req, res, next) => 
{
    const { refreshToken } = req.params;
    if (refreshToken in refreshTokens) {
        delete refreshTokens[refreshToken];
    }

    res.send(204);
});

app.post('/restaurant-reservation', passport.authenticate('jwt', {session: false}), (req, res) => 
{
    const { user } = req;
    const { guestsCount } = req.body;

    res.json({user, guestsCount});
});

app.get('/user-accessible', authorize(), (req, res) => 
{
    res.json({message: 'for all users', user: req.user});
});

app.get('/admin-accessible', authorize('admin'), (req,res) => 
{
    res.json({message: 'for admins only', user: req.user});
});


function authorize(roles = []) 
{
    if (typeof roles === 'string') {
        roles = [roles];
    }

    return [
        passport.authenticate('jwt', {session: false}),

        (req, res, next) => 
        {
            if (roles.length > 0 && !roles.includes(req.user.role)) {
                return res.status(403).json({message: 'No access'});
            };

            return next();
        }
    ];
}

app.listen(8086);
