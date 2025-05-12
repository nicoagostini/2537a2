const express = require('express');
const dotenv = require('dotenv');
const session = require('express-session');
const bcrypt = require('bcrypt');
const MongoStore = require('connect-mongo'); 
const MongoClient = require('mongodb').MongoClient;
const Joi = require('joi');


dotenv.config();

const saltRounds = Number(process.env.SALT_ROUNDS);

const expireTime = parseInt(process.env.EXPIRE_TIME);

const port = process.env.PORT || 3000;

const mongoUri = process.env.MONGO_URI;

const client = new MongoClient(mongoUri);

const app = express();

app.set('view engine', 'ejs');


app.use(express.json());
app.use(express.urlencoded({ extended: false }));


app.use("/public", express.static("./public"));


async function connectToDB() {
    try {
      await client.connect();
      console.log('Connected to MongoDB Atlas');
      return client.db(process.env.DB_NAME);
    } catch (e) {
      console.error('MongoDB connection failed:', e);
      return;
    }
}


app.use(session({
    secret: process.env.SESSION_SECRET,
    store: MongoStore.create({ mongoUrl: mongoUri, crypto: { secret: process.env.SESSION_SECRET } }),
    resave: true,
    saveUninitialized: false,
    cookie: {
        maxAge: 600000
    }
}));

app.get('/', (req, res) => {

    if(!req.session.authenticated){
        console.log("User not authenticated");
        res.render('index', { session: req.session, title: "Home" });
        return;
    }
    console.log("User authenticated");
    res.render('index', { session: req.session, title: "Members" });
    return;
});

app.get('/login', (req, res) => {
    res.render('login', { error: null, title: "Login" });
    return;
});

app.post('/login', async (req, res) => {
    
    if(req.session.authenticated){
        console.log("User already logged in");
        res.redirect('/members');
        return;
    }

    var { username, password } = req.body;
    var db = await connectToDB();

    const schema = Joi.object(
        {
        username: Joi.string().email().required(),
        password: Joi.string().max(20).required()
        });
    const validationResult = schema.validate(req.body);
    if(validationResult.error){
        console.log("Validation failed");
        res.render('signupError', { error: validationResult.error.details[0].message, title: "Signup Error" });
        return;
    }
    try{
        
        var user = await db.collection('users').findOne({ username: username });

        if(user.username == username){
            if(bcrypt.compareSync(password, user.password)){
                req.session.authenticated = true;
                req.session.name = user.name;
                req.session.admin = user.admin;
                console.log("User logged in");
                console.log(req.session);
                res.redirect('/members');
                return;
            }
            console.log("Invalid password but checking");
            res.render('login', { error: 'Invalid password', title: "Login" });
            return;
        }
        console.log("Invalid username ");
        res.render('login', { error: 'Invalid Email', title: "Login" });
        return;

    }catch(e){
        console.log("User not found");
        res.render('login', { error: 'User not found', title: "Login" });
        return;
    }

});

app.get('/logout', (req, res) => {
    req.session.destroy();
    console.log("User logged out");
    res.redirect('/');
    return;
});

app.get('/signup', (req, res) => {
    res.render('signup', { title: "Signup" });
});
app.post('/signup', async (req, res) => {

    const schema = Joi.object(
        {
        name: Joi.string().alphanum().max(20).required(),   
        username: Joi.string().email().required(),
        password: Joi.string().max(20).required()
        });

    const validationResult = schema.validate(req.body);
    if(validationResult.error){
        console.log("Validation failed");
        res.render('signupError', { error: validationResult.error.details[0].message, title: "Signup Error" });
        return;
    }
    var { name, username, password } = req.body;
    if(!name){
        res.render('signupError', { error: 'Name is required', title: "Signup Error" });
        return;
    }
    if(!username){
        res.render('signupError', { error: 'Email is required', title: "Signup Error" });
        return;
    }
    if(!password){
        res.render('signupError', { error: 'Password is required', title: "Signup Error" });
        return;
    }

    var db = await connectToDB();

    if(await db.collection('users').findOne({ username: username })) {
        res.render('signupError', { error: 'Email already exists', title: "Signup Error" });
        return;
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);
    var user = {
        name: name,
        username: username,
        password: hashedPassword,
        admin: false
    };

    try{
        await db.collection('users').insertOne(user);
        console.log("User created: " + user.username);
        res.redirect('/login');
        return;
    }catch(e){
        console.log("User not created: " + user.username);
        console.log(e);
        res.redirect('/signup');
        return;
    }
})

app.get('/members', (req, res) => {
    if(!req.session.authenticated){
        console.log("User not authenticated");
        res.redirect('/login');
        return;
    }
    console.log("User authenticated");
    res.render('members', { name: req.session.name , images: ["1.jpg", "2.jpg", "3.jpg"], error: null, title: "Members", session: req.session});
    return;
})

app.get('/admin', async (req, res) => {
    if(!req.session.authenticated){
        console.log("User not authenticated");
        res.redirect('/login');
        return;
    }
    if(!req.session.admin){
        console.log("User not admin");
        req.session.error = "You are not authorized to access this page";
        res.redirect('/members');
        return;
    }
    db = await connectToDB();
    users = await db.collection('users').find().toArray();
    console.log(users);
    console.log("User authenticated");
    res.render('admin', { title: "Admin", session: req.session, users: users});
    return;
})

app.get('/admin/promote/:username', async (req, res) => {
    if(!req.session.authenticated){
        console.log("User not authenticated");
        res.redirect('/login');
        return;
    }
    if(!req.session.admin){
        console.log("User not admin");
        req.session.error = "You are not authorized to access this page";
        res.redirect('/members');
        return;
    }
    var db = await connectToDB();
    var user = await db.collection('users').findOne({ username: req.params.username });
    if(!user){
        console.log("User not found");
        res.redirect('/admin');
        return;
    }
    await db.collection('users').updateOne({ username: req.params.username }, { $set: { admin: true } });
    console.log("User promoted");
    res.redirect('/admin');
    return;
})

app.get('/admin/demote/:username', async (req, res) => {
    if(!req.session.authenticated){
        console.log("User not authenticated");
        res.redirect('/login');
        return;
    }
    if(!req.session.admin){
        console.log("User not admin");
        req.session.error = "You are not authorized to access this page";
        res.redirect('/members');
        return;
    }
    db = await connectToDB();
    user = await db.collection('users').findOne({ username: req.params.username });
    if(!user){
        console.log("User not found");
        res.redirect('/admin');
        return;
    }
    if(user.admin){
        user.admin = false;
        await db.collection('users').updateOne({ username: req.params.username }, { $set: { admin: false } });
    }
    console.log("User demoted");
    res.redirect('/admin');
    return;
})

app.get('/*splat', (req, res) => {
    res.status(404);
    res.render('404', { title: "404 Not Found" });
    return;
});

app.listen(port, () => {
    console.log('Server is running on port ' + port);
});