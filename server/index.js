require('dotenv').config();
const express = require('express');
const massive = require('massive');
const session = require('express-session');
const app = express();
const ac = require('./controllers/authController');
const pc = require('./controllers/postsController');

const {SERVER_PORT, DATABASE_STRING, SESSION_SECRET} = process.env;

app.use((req, res, next) => {
   console.log('========== Server hit ==========');
   next();
});

app.use(express.json());

app.use(session({
   secret: SESSION_SECRET,
   resave: false,
   saveUninitialized: true,
   cookie: {
      maxAge: 1000 * 60 * 60 * 24 * 7
   }
}))

massive(DATABASE_STRING).then(db => {
   app.set('db', db);
   console.log('Database linked');
});

app.get('/api/auth/me', ac.getSession);
app.post('/api/auth/register', ac.register);
app.post('/api/auth/login', ac.login);
app.put('/api/auth/updateusername/:username', ac.updateUsername)
app.post('/api/auth/logout', ac.logout);

app.get('/api/posts/getAll/:showOwnBool', pc.getAll);
app.get('/api/posts/getOne/:postId', pc.getOne);
app.post('/api/posts/create', pc.create);

app.listen(SERVER_PORT, () => console.log(`Server listening on ${SERVER_PORT}`));