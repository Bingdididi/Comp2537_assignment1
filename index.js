
require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3000;


const app = express();

const Joi = require("joi");
const path = require('path');



const expireTime = 24 * 60 * 60 * 1000; //expires after 1 day  (hours * minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var {database} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
})

app.use(session({ 
    secret: node_session_secret,
	store: mongoStore, //default is memory store 
	saveUninitialized: false, 
	resave: true
}
));

app.get('/', (req, res) => {
    if (req.session.user) {
        // User is logged in
        res.send(`
          <h1>Welcome, ${req.session.user.name}!</h1>
          <br>
          <button style="background-color: #4CAF50; border: none; color: white; padding: 15px 32px; text-align: center; text-decoration: none; display: inline-block; font-size: 16px;" onclick="window.location.href='/members'">Members Area</button>
          <br><br>
          <button style="background-color: #f44336; border: none; color: white; padding: 15px 32px; text-align: center; text-decoration: none; display: inline-block; font-size: 16px;" onclick="window.location.href='/logout'">Logout</button>
        `);
    } else {
      res.send(`<h1>Welcome to our website</h1>
      <style>
        .button {
          display: inline-block;
          padding: 10px 20px;
          font-size: 18px;
          cursor: pointer;
          text-align: center;
          text-decoration: none;
          outline: none;
          color: #fff;
          background-color: #4CAF50;
          border: none;
          border-radius: 15px;
          box-shadow: 0 9px #999;
          margin-right: 10px; /* Add space to the right of the button */
        }
  
        .button:hover {background-color: #3e8e41}
  
        .button:active {
          background-color: #3e8e41;
          box-shadow: 0 5px #666;
          transform: translateY(4px);
        }
      </style>
      <div>
        <a href="/signup" class="button">Sign up</a>
        <a href="/login" class="button">Log in</a>
      </div>`);
    }
  });
  




app.get('/nosql-injection', async (req,res) => {
	var username = req.query.user;

	if (!username) {
		res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
		return;
	}
	console.log("user: "+username);

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(username);

	//If we didn't use Joi to validate and check for a valid URL parameter below
	// we could run our userCollection.find and it would be possible to attack.
	// A URL parameter of user[$ne]=name would get executed as a MongoDB command
	// and may result in revealing information about all users or a successful
	// login without knowing the correct password.
	if (validationResult.error != null) {  
	   console.log(validationResult.error);
	   res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
	   return;
	}	

	const result = await userCollection.find({username: username}).project({username: 1, password: 1, _id: 1}).toArray();

	console.log(result);
}); 
   


app.get('/signup', (req, res) => {
    res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Sign Up</title>
        <style>
          body {
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            font-family: Arial, sans-serif;
          }
          form {
            display: flex;
            flex-direction: column;
            width: 300px;
          }
          h2 {
            margin-bottom: 20px;
          }
          label, input {
            margin-bottom: 10px;
          }
          input[type="submit"] {
            cursor: pointer;
          }
        </style>
      </head>
      <body>
        <form action="/signup" method="POST">
          <h2>Create user</h2>
          <label for="name">Name:</label>
          <input type="text" id="name" name="name" placeholder="Enter your name" required>
    
          <label for="email">Email:</label>
          <input type="email" id="email" name="email" placeholder="example@example.com" required>
    
          <label for="password">Password:</label>
          <input type="password" id="password" name="password" placeholder="Enter your password" required>
    
          <input type="submit" value="Sign Up">
        </form>
      </body>
      </html>
    `);
  });
  
  const userSchema = Joi.object({
    name: Joi.string().min(1).max(255).required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(6).max(255).required(),
  });


  app.post('/signup', async (req, res) => {
    // Validate input and check for missing fields
    const result = userSchema.validate(req.body);
    if (result.error) {
      res.status(400).send(result.error.details[0].message);
      return;
    }
  
    // Add user to MongoDB, create session, and redirect to /members
    try {
      const existingUser = await userCollection.findOne({ email: req.body.email });
  
      if (existingUser) {
        res.status(400).send('Email already exists');
        return;
      }
  
      const hashedPassword = await bcrypt.hash(req.body.password, 10);
      const newUser = {
        name: req.body.name,
        email: req.body.email,
        password: hashedPassword
      };
  
      await userCollection.insertOne(newUser);
      req.session.user = newUser;
      res.redirect('/members');
    } catch (err) {
      console.log(err);
      res.status(500).send('Server error');
    }
  });
  

  
  


app.get('/login', (req, res) => {
    res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Login</title>
        <style>
          body {
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            font-family: Arial, sans-serif;
          }
          form {
            display: flex;
            flex-direction: column;
            width: 300px;
          }
          h2 {
            margin-bottom: 20px;
          }
          label, input {
            margin-bottom: 10px;
          }
          input[type="submit"] {
            cursor: pointer;
          }
        </style>
      </head>
      <body>
        <form action="/login" method="POST">
          <h2>Log in</h2>
          <label for="email">Email:</label>
          <input type="email" id="email" name="email" placeholder="example@example.com" required>
  
          <label for="password">Password:</label>
          <input type="password" id="password" name="password" placeholder="Enter your password" required>
  
          <input type="submit" value="Login">
        </form>
      </body>
      </html>
    `);
  });
  
  

  app.post('/login', async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;
  
    const schema = Joi.string().email().required();
    const validationResult = schema.validate(email);
    if (validationResult.error != null) {
      console.log(validationResult.error);
      res.redirect('/login');
      return;
    }
  
    const result = await userCollection
      .find({ email: email })
      .project({ email: 1, password: 1, name: 1, _id: 1 }) // Add 'name' field to the projection
      .toArray();
  
    console.log(result);
    if (result.length != 1) {
      console.log('user not found');
      res.redirect('/login');
      return;
    }
    if (await bcrypt.compare(password, result[0].password)) {
      console.log('correct password');
      req.session.authenticated = true;
      req.session.user = {
        email: email,
        name: result[0].name // Assuming the user's name is stored in the 'name' field
      };
      req.session.cookie.maxAge = expireTime;
  
      res.redirect('/');
      return;
    } else {
        console.log('user or password not found');
        res.redirect('/loginSubmit?error=userNotFound');
        return;
      }
    });
    
    app.get('/loginSubmit', (req, res) => {
      let error;
      if (req.query.error === 'userNotFound') {
        error = 'User or password not found. Please check your email and password and try again.';
      } else {
        error = '';
      }
    
      res.send(`
        <h1>Login Failed</h1>
        <p>${error}</p>
        <a href="/login">Back to Login</a>
      `);
    });
  
  



  
  
  

  
  
  
  
  
  app.get('/members', (req, res) => {
    if (!req.session.user) {
      res.redirect('/');
      return;
    }
  
    // Generate a random number between 1 and 3 to choose an image
    const randomImageNumber = Math.floor(Math.random() * 3) + 1;
  
    let imageHTML = '';
  
    if (randomImageNumber === 1) {
      imageHTML = "<img src='/bicycle.jpg' alt='' style='max-width: 250px;' />";
    } else if (randomImageNumber === 2) {
      imageHTML = "<img src='/tennis.jpg' alt='' style='max-width: 250px;' />";
    } else {
      imageHTML = "<img src='/sports.jpg' alt='' style='max-width: 250px;' />";
    }
  
    res.send(`
      <h1>Hello, ${req.session.user.name}!</h1>
      <div>${imageHTML}</div>
      <button onclick="window.location.href='/logout'">Logout</button>
    `);
  });
  
  app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
  });
  
  




app.use(express.static(__dirname + "/public"));

app.get("*", (req,res) => {
	res.status(404);
	res.send("Page not found - 404");
})

app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 