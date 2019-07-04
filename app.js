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
    
    const accessToken = generateAccessToken(username, 'admin');    
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

app.post('/token', (req, res) => 
{
    const { username, refreshToken } = req.body;
    
    if (refreshToken in refreshTokens && refreshTokens[refreshToken] === username) {        
        const accessToken = generateAccessToken(username, 'admin');
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

app.listen(8080);
