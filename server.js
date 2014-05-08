var express = require('express');
var app = express();
var engine = require('ejs-locals')

var passport = require('passport'),
    LocalStrategy = require('passport-local').Strategy,
    mongodb = require('mongodb'),
    mongoose = require('mongoose'),
    bcrypt = require('bcrypt'),
    SALT_WORK_FACTOR = 10;

mongoose.connect('localhost', 'test');
var db = mongoose.connection;
db.on('error', console.error.bind(console, 'connection error:'));
db.once('open', function callback() {
    console.log('Connected to DB');
});

var userSchema = mongoose.Schema({
    name: {
        type: String,
        required: true
    },
    surname: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    },
    knows: {
        type: [String],
        required: true
    },
    wants: {
        type: [String],
        required: true
    },
    about: {type: String, required: false},
    image: {
      type: String,
      required: false,
      default: '/img/default.img'
    }
});

var classSchema = mongoose.Schema({
    user1: {
        type: String,
        requred: true
    },
    user2: {
        type: String,
        required: true
    },
    completed: {
        type: Date,
        required: false
    },
    accepted: {
        type: Boolean,
        required: false
    }
});

userSchema.methods.comparePassword = function(candidatePassword, cb) {
    bcrypt.compare(candidatePassword, this.password, function(err, isMatch) {
        if (err) return cb(err);
        cb(null, isMatch);
    });
};

userSchema.pre('save', function(next) {
    var user = this;

    if (!user.isModified('password')) return next();

    bcrypt.genSalt(SALT_WORK_FACTOR, function(err, salt) {
        if (err) return next(err);

        bcrypt.hash(user.password, salt, function(err, hash) {
            if (err) return next(err);
            user.password = hash;
            next();
        });
    });
});

var User = mongoose.model('User', userSchema);
var Class = mongoose.model('Class', classSchema);

User.update({_id: "536a3d87360c34b5264ef939"}, {$set:{image: '/img/bob.jpg'}}, function(err, data){
  console.log(err);
});
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
    User.findById(id, function(err, user) {
        done(err, user);
    });
});

passport.use(new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password'
}, function(email, password, done) {
    User.findOne({
        email: email
    }, function(err, user) {
        if (err) {
            return done(err);
        }
        if (!user) {
            return done(null, false, {
                message: 'Unknown user ' + email
            });
        }
        user.comparePassword(password, function(err, isMatch) {
            if (err) return done(err);
            if (isMatch) {
                return done(null, user);
            } else {
                return done(null, false, {
                    message: 'Invalid password'
                });
            }
        });
    });
}));

function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/login')
}

function which(item, wants) {
    for (var i = 0; i < item.length; i++) {
        for (var j = 0; j < wants.length; j++) {
            if (item[i] == wants[j])
                return item[i];
        };
    };

    return "";
}

function combine(data, user) {
    var temp = {};
    for (var i = 0; i < data.length; i++) {
        var lang = which(data[i].knows, user['wants']);
        if (lang in temp)
            temp[lang] += [data[i]];
        else
            temp[lang] = [data[i]];
    };

    return temp;
}

app.use(express.static(process.cwd() + '/public'));
app.engine('ejs', engine);
app.use(express.bodyParser());
app.use(express.cookieParser('keyboard cat'));
app.use(express.session({
    secret: "my secret"
}));
app.use(express.methodOverride());
app.use(passport.initialize());
app.use(passport.session());
app.use(app.router);
app.set('view engine', 'ejs');


app.get('/', function(req, res) {
    if (req.isAuthenticated())
        res.render('dashboard', {
            user: req.user
        });
    else
        res.render('welcome', {
            user: req.user
        });
});

app.get('/classroom/:classID', ensureAuthenticated, function(req, res) {
    Class.findOne({
        _id: req.params.classID
    }, function(err, data) {
        res.render('classroom', {
            user: req.user,
            classInfo: data
        });
    });

});

app.get('/search', ensureAuthenticated, function(req, res) {
    User.find({
        knows: req.user.wants
    }, function(err, data) {

        if (err != null)
            res.render('search', {
                data: err,
                user: req.user
            });
        else {
            var temp = combine(data, req.user);
            res.render('search', {
                data: temp,
                user: req.user
            });
        }
    });
});

app.post('/search', function(req, res) {
    User.find(req.body, function(err, data) {
        if (err != null)
            res.json(err);
        else
            res.json(combine(data, req.user));
    });
});

app.get('/register', function(req, res) {
    res.render('register', {
        user: req.user
    });
});

app.post('/register', function(req, res) {
    var temp = req.body;
    temp['knows'] = req.body['knows'].split(',');
    temp['wants'] = req.body['wants'].split(',');

    console.log(temp);

    var user = new User(temp);
    user.save(function(err) {
        if (err) {
            console.log(err);
        } else {
            console.log('user: ' + user.email + " saved.");
        }
    });
});

app.get('/login', function(req, res) {
    res.render('login', {
        user: req.user
    });
});

app.post('/login', function(req, res, next) {
    console.log(req.body);
    passport.authenticate('local', function(err, user, info) {
        console.log(user);
        if (err) {
            return next(err)
        }
        if (!user) {
            console.log(info.message);
            req.session.messages = [info.message];
            return res.redirect('/login')
        }
        req.logIn(user, function(err) {
            if (err) {
                return next(err);
            }
            return res.redirect('/');
        });
    })(req, res, next);
});

app.get('/logout', function(req, res) {
    req.logout();
    res.redirect('/');
});


app.get('/api/user', function(req, res){
  User.findOne({_id:req.param('id')}, function(err, data){
    res.json(data);
  });
});

var server = app.listen(3000, function() {
    console.log('Listening on port %d', server.address().port);
})

var clients = {};

var io = require('socket.io').listen(server);

io.sockets.on('connection', function(socket) {
    socket.emit('news', {
        hello: 'world'
    });
    socket.on('beginCall', function(data) {

        User.findOne({
            _id: data.from
        }, function(err, d) {
            _class = new Class({
                user1: data.from,
                user2: data.user
            });
            _class.save(function(e, newClass) {
                var temp = {};
                temp['name'] = d['name'] + ' ' + d['surname'];
                temp['langrequested'] = data['lang'];
                temp['langoffered'] = d['knows'];
                clients[data.user].emit('incomingCall', {
                    data: temp,
                    classID: newClass.id
                });
            });

        });

    });

    socket.on('connect', function(data) {
        clients[data['id']] = socket;
    });

    socket.on('accept', function(data) {
        Class.findOne({
            _id: data.classID
        }, function(err, _class) {
            clients[_class['user1']].emit('startCall', {
                classID: data.classID
            });
            clients[_class['user2']].emit('startCall', {
                classID: data.classID
            });
            //update class to accepted and started
        });
    });

    socket.on('send', function(data){
      clients[data.user].emit('send', {text: data.text});
    });
});