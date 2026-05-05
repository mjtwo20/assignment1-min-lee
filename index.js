/*
Reference: The sample code
https://github.com/greencodecomments/2537_Demo_1/
https://coreui.io/answers/how-to-use-joi-for-validation-in-nodejs/
*/
require("./utils.js");
require("dotenv").config();
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo").default;
const bcrypt = require("bcrypt");
const saltRounds = 12;
const port = process.env.PORT || 3000;
const app = express();
const Joi = require("joi");
const expireTime = 1 * 60 * 60 * 1000;

// Secret Information Section
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

const { database } = include("databaseConnection");
const userCollection = database.db(mongodb_database).collection("users");

app.use(express.urlencoded({ extended: false }));
app.use(express.json());

var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_database}`,
  crypto: {
    secret: mongodb_session_secret,
  },
});

app.use(
  session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true,
  }),
);

// Routing
app.get("/", (req, res) => {
  if (!req.session.authenticated) {
    res.send(`
            <form action="/signup", method="GET">
                <button type="submit">Sign up</button>
            </form>    
            <form action="/login", method="GET">
                <button type="submit">Log in</button>
            </form>  
            `);
  } else {
    res.send(`
            <h2>Hello, ${req.session.name}!</h2>
            <form action="/members" method="GET">
                <button type="submit">Go to Members Area</button>
            </form>
            <form action="/logout" method="GET">
                <button type="submit">Logout</button>
            </form>
        `);
  }
});

// signup
app.get("/signup", (req, res) => {
  var html = `
            <p>create user</p>
            <form action ="/signupSubmit" method="POST">
                <input name="name" type="text" placeholder="name"><br>
                <input name="email" type="email" placeholder="email"><br>
                <input name="password" type="password" placeholder="password"><br>
                <button type="submit">Submit</button>
            </form>
        `;
  res.send(html);
});

// signupSubmit
app.post("/signupSubmit", async (req, res) => {
  var name = req.body.name;
  var email = req.body.email;
  var password = req.body.password;

  const schema = Joi.object({
    name: Joi.string().max(20).required(),
    email: Joi.string().email().required(),
    password: Joi.string().max(20).required(),
  });

  const validationResult = schema.validate({ name, email, password });

  if (validationResult.error != null) {
    var errorMessage = validationResult.error.details[0].message;
    var html = `
        <p>${errorMessage}</p>
        <a href = "/signup">Try again</a>   
    `;
    res.send(html);
    return;
  }

  var hashedPassword = await bcrypt.hash(password, saltRounds);
  await userCollection.insertOne({
    name: name,
    email: email,
    password: hashedPassword,
  });
  console.log("Inserted user");

  req.session.authenticated = true;
  req.session.name = name;
  req.session.cookie.maxAge = expireTime;
  res.redirect("/members");
});

// login
app.get("/login", (req, res) => {
  var html = `
        <p>log in</p>
        <form action="/loggingin" method="POST">
            <input name="email" type="email" placeholder="email"><br>
            <input name="password" type="password" placeholder="password"><br>
            <button type="submit">Submit</button>
        </form>
    `;
  res.send(html);
});

//logginin
app.post("/loggingin", async (req, res) => {
  var email = req.body.email;
  var password = req.body.password;

  const schema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().max(20).required(),
  });

  const validationResult = schema.validate({ email, password });
  if (validationResult.error != null) {
    res.redirect("/login");
    return;
  }

  const result = await userCollection
    .find({ email: email })
    .project({ name: 1, email: 1, password: 1, _id: 1 })
    .toArray();

  if (result.length != 1) {
    var html = `
        User and password not found.<br>
        <a href="/login">Try again</a>
    `;
    res.send(html);
    return;
  }

  if (await bcrypt.compare(password, result[0].password)) {
    console.log("correct password");
    req.session.authenticated = true;
    req.session.name = result[0].name;
    req.session.cookie.maxAge = expireTime;

    res.redirect("/members");
    return;
  } else {
    var html = `
      Invalid email/password<br>
      <a href="/login">Try again</a>
    `;
    res.send(html);
    return;
  }
});

// logout
app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

// members
app.get("/members", (req, res) => {
  if (!req.session.authenticated) {
    res.redirect("/");
    return;
  }
  var randomImageNum = Math.floor(Math.random() * 3) + 1;
  var html = `
        <h2> Hello, ${req.session.name}.</h2>
        <img src="/cat${randomImageNum}.JPG" style="width:250px;"><br>
        <a href="/logout"><button>Sign out</button></a>
    `;
  res.send(html);
});

app.use(express.static(__dirname + "/public"));

// 404 Handler
app.use((req, res) => {
  res.status(404);
  var html = `
    <h3>Page not found - 404</h3>
    <p> It does not exist </p>
    <a href="/"><button>Home</button></a> 
  `;

  res.send(html);
});

// Error Handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: "Internal server error" });
});

// listen
app.listen(port, () => {
  console.log(`Server listening on http://localhost:${port}`);
});
