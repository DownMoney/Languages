var express = require('express');
var app = express();
var engine = require('ejs-locals')

var passport = require('passport')
  , LocalStrategy = require('passport-local').Strategy
  , mongodb = require('mongodb')
  , mongoose = require('mongoose')
  , bcrypt = require('bcrypt')
  , SALT_WORK_FACTOR = 10;

mongoose.connect('localhost', 'test');
var db = mongoose.connection;
db.on('error', console.error.bind(console, 'connection error:'));
db.once('open', function callback() {
  console.log('Connected to DB');
});

var userSchema = mongoose.Schema({
  name: {type: String, required: true},
  surname: {type: String, required: true},
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true},
  knows: {type: [String], required: true},
  wants: {type: [String], required: true}
});

userSchema.methods.comparePassword = function(candidatePassword, cb) {
	bcrypt.compare(candidatePassword, this.password, function(err, isMatch) {
		if(err) return cb(err);
		cb(null, isMatch);
	});
};

userSchema.pre('save', function(next) {
	var user = this;

	if(!user.isModified('password')) return next();

	bcrypt.genSalt(SALT_WORK_FACTOR, function(err, salt) {
		if(err) return next(err);

		bcrypt.hash(user.password, salt, function(err, hash) {
			if(err) return next(err);
			user.password = hash;
			next();
		});
	});
});

var User = mongoose.model('User', userSchema);
/*var user = new User({ username: 'bob', email: 'bob@example.com', password: 'secret' });
user.save(function(err) {
  if(err) {
    console.log(err);
  } else {
    console.log('user: ' + user.username + " saved.");
  }
});*/




passport.serializeUser(function(user, done) {	
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function (err, user) {
    done(err, user);
  });
});

passport.use(new LocalStrategy({usernameField : 'email', passwordField : 'password'},function(email, password, done) {
  User.findOne({ email: email }, function(err, user) {
    if (err) { return done(err); }
    if (!user) { return done(null, false, { message: 'Unknown user ' + email}); }
    user.comparePassword(password, function(err, isMatch) {
      if (err) return done(err);
      if(isMatch) {
        return done(null, user);
      } else {
        return done(null, false, { message: 'Invalid password' });
      }
    });
  });
}));

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) { return next(); }
  res.redirect('/login')
}


app.use(express.static(process.cwd() + '/public'));
app.engine('ejs', engine);
app.use(express.bodyParser());
app.use(express.cookieParser('keyboard cat'));
app.use(express.session( {secret : "my secret"}));
app.use(express.methodOverride());
  app.use(passport.initialize());
  app.use(passport.session());
  app.use(app.router);
app.set('view engine', 'ejs');


app.get('/', function(req, res){
	if (req.isAuthenticated())
		res.render('dashboard', {user: req.user});
	else
		res.render('welcome', {user: req.user});
});

app.get('/classroom', ensureAuthenticated, function(req, res){
	res.render('classroom', {user: req.user});
});

app.get('/search', function(req, res){
	res.render('search', {user: req.user});
});

app.get('/register', function(req, res){
	res.render('register', {user: req.user});
});

app.post('/register', function(req, res){
	var temp = req.body;
	temp['knows'] = req.body['knows'].split(',');
	temp['wants'] = req.body['wants'].split(',');

	console.log(temp);

	var user = new User(temp);
	user.save(function(err) {
	  if(err) {
	    console.log(err);
	  } else {
	    console.log('user: ' + user.email + " saved.");
	  }
	});
});

app.get('/login', function(req, res){
	res.render('login', {user: req.user});
});

app.post('/login', function(req, res, next) {
	console.log(req.body);
  passport.authenticate('local', function(err, user, info) {
  	console.log(user);
    if (err) { return next(err) }
    if (!user) {
    	console.log(info.message);
      req.session.messages =  [info.message];
      return res.redirect('/login')
    }
    req.logIn(user, function(err) {
      if (err) { return next(err); }
      return res.redirect('/');
    });
  })(req, res, next);
});

app.get('/logout', function(req, res){
  req.logout();
  res.redirect('/');
});


var server = app.listen(3000, function() {
    console.log('Listening on port %d', server.address().port);
})


var io = require('socket.io').listen(server);

io.sockets.on('connection', function (socket) {
  socket.emit('news', { hello: 'world' });
  socket.on('my other event', function (data) {
    console.log(data);
  });
});
