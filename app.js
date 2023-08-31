const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const passportLocalMongoose = require('passport-local-mongoose');
const dotenv = require('dotenv');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');



// Load environment variables from .env file
dotenv.config();

const app = express();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));
app.set('view engine', 'ejs');

app.use(session({
  secret: process.env.SECRET_KEY, // Replace with a strong secret key
  resave: false,
  saveUninitialized: false,
}));

// Initialize passport and session for authentication
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://127.0.0.1:27017/userDB", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// Event listener for connection timeout
mongoose.connection.on('timeout', () => {
  console.log('MongoDB connection timeout. Check if the MongoDB server is running.');
  process.exit(1); // Exit the application on timeout
});

// Event listener for successful connection
mongoose.connection.on('connected', () => {
  console.log('Connected to MongoDB');
});

// Event listener for connection error
mongoose.connection.on('error', (err) => {
  console.error('Error connecting to MongoDB:', err);
});

passport.use(new GoogleStrategy({
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: 'http://localhost:3000/auth/google/secrets',
},
function(accessToken, refreshToken, profile, cb) {
  // This function will be called when the user authorizes the app with Google
  // You can create or update a user record in the database here
  // The "profile" object contains information about the authenticated user
  // For simplicity, let's assume the "email" is the unique identifier for a user
  User.findOrCreate({ email: profile.emails[0].value, googleId: profile.id }, function (err, user) {
    return cb(err, user);
  });
}
));



app.get("/", function (req, res) {
  res.render("home");
});

app.get("/login", function (req, res) {
  res.render("login");
});

app.get("/register", function (req, res) {
  res.render("register");
});

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
  },
  googleId: {
    type: String,
    unique: true,
  },
});

userSchema.plugin(findOrCreate);

// Use passport-local-mongoose plugin to simplify passport configuration
userSchema.plugin(passportLocalMongoose, { usernameField: 'email' });

// Create the User model
const User = mongoose.model('User', userSchema);

// Configure passport to use LocalStrategy for authentication
passport.use(User.createStrategy());

// Serialize and deserialize user to maintain session
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

const secretSchema = new mongoose.Schema({
  secretText: {
    type: String,
    required: true,
  },
});

// Create the Secret model
const Secret = mongoose.model('Secret', secretSchema);


// Register route
app.post('/register', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Check if the email is already registered
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ message: 'Email already registered' });
    }

    // Create a new user using passport-local-mongoose's register method
    const newUser = await User.register({ email }, password);

    // Save the Google ID from the Google OAuth profile to the newUser object
    if (req.session.passport && req.session.passport.user) {
      newUser.googleId = req.session.passport.user.profile.id;
      await newUser.save();
    }

    // Redirect to the secrets page after successful registration
    res.redirect('/secrets');
  } catch (error) {
    console.error('Error registering user:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Login route
app.post('/login', passport.authenticate('local', {
  successRedirect: '/secrets',
  failureRedirect: '/login',
}));

// Secrets route
app.get("/secrets", async function (req, res) {
  try {
    // Check if the user is authenticated (logged in)
    if (req.isAuthenticated()) {
      // Find all the secrets in the database using async/await
      const secrets = await Secret.find({});
      // Render the secrets page and pass the secrets data to the template
      res.render("secrets", { secrets: secrets });
    } else {
      res.redirect("/login"); // Redirect to login page if not authenticated
    }
  } catch (err) {
    console.error('Error fetching secrets:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Add this route handler for the "GET" request to "/submit"
app.get('/submit', function (req, res) {
  res.render('submit'); // Renders the "submit.ejs" template
});


// Submit route using async/await
app.post('/submit', async function (req, res) {
  // Get the secret text from the form submission
  const secretText = req.body.secret;

  // console.log('Reached /submit route.'); // Add this console log

  try {
    // Create a new Secret document and save it to the database using async/await
    await Secret.create({ secretText });
    // Redirect to the secrets page after successful submission
    res.redirect('/secrets');
  } catch (err) {
    console.error('Error saving secret:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});



// Logout route
app.get('/logout', function (req, res) {
  // Passport provides a logout() function to terminate a user's login session
  req.logout(function(err) {
    if (err) {
      console.error('Error logging out:', err);
    }
    res.redirect('/');
  });
});

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/auth/google/secrets',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect to the secrets page
    res.redirect('/secrets');
  }
);

app.listen(3000, function () { console.log("server started at port 3000"); });
