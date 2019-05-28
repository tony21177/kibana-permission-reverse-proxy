var express = require('express');
var bodyParser = require('body-parser');
// var cookieParser = require('cookie-parser');
var session = require('express-session');
var morgan = require('morgan');
var jwt = require('jsonwebtoken');
var {User,UserRoles,UserPerm} = require('./models/user');
var { base64encode, base64decode } = require('nodejs-base64');
// var MemoryStore = require('memorystore')(session);


// invoke an instance of express application.
var app = express();

// set our application port
app.set('port', 8082);

// set morgan to log info about our requests for development use.
app.use(morgan('dev'));

// initialize body-parser to parse incoming parameters requests to req.body
app.use(bodyParser.json());

// don't use cookieParser 
//Since version 1.5.0, the cookie-parser middleware no longer needs to be used for this module to work. This module now directly reads and writes cookies on req/res. Using cookie-parser may result in issues if the secret is not the same between this module and cookie-parser
// app.use(cookieParser());

// initialize express-session to allow us track the logged-in user across sessions.


app.use(session({
    key: 'user_sid',
    secret: '123456',
    resave: false,
    saveUninitialized: false,
    // store: new MemoryStore({
    //     checkPeriod: 86400000 // prune expired entries every 24h
    //   }),
    cookie: {
        path:'/',
        httpOnly:false,
        secure:false,
        maxAge: 1800 * 1000
    }
}));




// This middleware will check if user's cookie is still saved in browser and user is not set, then automatically log the user out.
// This usually happens when you stop your express server after login, your cookie still remains saved in the browser.
// app.use((req, res, next) => {
//     if (req.cookies.user_sid && !req.session.user) {
//         res.clearCookie('user_sid');        
//     }
//     next();
// });


// middleware function to check for logged-in users
var sessionChecker = (req, res, next) => {
    console.log("----------------------sessionChecker---------------------")
    // console.log("cookie:"+req.cookies.user_sid);
    // console.log("user:"+req.session.user);
    // if (req.session.user && req.cookies.user_sid) {
        if (req.session.user ) {
        res.redirect('http://192.168.28.169:8081/dashboard');
    } else {
        next();
    }    
};


// route for Home-Page
app.get('/', sessionChecker, (req, res) => {
    res.redirect('http://192.168.28.169:8081');
});


// get user's kibana permisssion

app.get('/kibana/permission/:username',(req,res)=>{
    UserPerm.findOne({ where: { username: req.params.username } }).then(function(userPerm){
        if(!userPerm){
            res.send({}).status(200).end();
        }else{
            res.send(userPerm.permission).status(200).end();
        }
    })
})


// route for user Login
app.route('/login')
    .get(sessionChecker, (req, res) => {
        res.sendFile('http://192.168.28.169:8081');
    })
    .post((req, res) => {
        
        var username = req.body.username,
            password = req.body.password;
        // console.log(req.body);

        

        
        User.findOne({ where: { username: username } }).then(function (user) {
            if (!user) {
                // console.log("no such account!");
                res.status(401).send({'status':'wrong account'}).end();
            } else if (!user.validPassword(password)) {
                // console.log("password wrong!");
                res.status(401).send({'status':'wrong password'}).end();
            } else {
                req.session.user = user.dataValues;
                // console.log("--------/login--------response----------------")
                // console.log(req.sessionID);
                // console.log("--------/login--------session----------------")
                // console.log(req.session);
                // console.log(generateKibanaToken);

                generateKibanaToken(user.username,user.password).then(
                    token=>{
                        // console.log("then---");
                        // console.log(token);


                        //set-Cookie
                        res.set({
                            'Set-Cookie':'kibana_token='+token+';HttpOnly;Path=/;domain='+'192.168.28.169'
                        }).status(200).send({'kibana_token':token}).end();


                        //by body
                        // res.status(200).send({'kibana_token':token}).end();
                    },
                    error=>{
                        // console.log(error)
                });
            }
        });
    });
const generateKibanaToken = (username,password)=>{
    var token = "";
    return UserPerm.findOne({ where: { username: username } }).then(function (userPerm) {
        if (!userPerm) {
            return Promise.reject("no setting")
        } else {
            
            const payload = {
                username:username,
                permission:userPerm.permission,
                exp: Math.floor(Date.now()/1000)+(30*60)
            }
            token = jwt.sign(payload,'123456')
            return token;
        }
    
    });
};

// route for user info
app.route('/user/info')
    .get((req, res) => {
        // console.log("---------------------------/user/getInfo----------------------------------")
        // console.log("--------/user/info--------session----------------")
        // console.log(req.sessionID);
        // console.log("--------/user/info--------session----------------")
        // console.log(req.session);
        
        // if (req.session.user && req.cookies.user_sid) {
        if (req.session.user ) {
            UserRoles.findAll({ where: { username: req.session.user.username } }).then(function(userRoles){
                if (!userRoles) {
                    // console.log("no such account!");
                    res.status(401).send({'status':'wrong account'}).end();
                }else{
                    let roleArray = []
                    userRoles.forEach(element => {
                        
                        roleArray.push(element.roleId);

                    });
                    
                    res.send({'user':req.session.user,'roles':roleArray}).end();
                }
            });
        } else {
            res.status(401).send("{'status':Please login first}").end();
            // res.redirect('http://192.168.28.169:8081');
        }
    });    


// start the express server
app.listen(app.get('port'), () => console.log(`App started on port ${app.get('port')}`));















//reverse proxy for kibana authc

var httpProxy = require('http-proxy');
//
// Create your proxy server and set the target in the options.
//
var proxy = httpProxy.createProxyServer()


const httpServer = express();
httpServer.use(bodyParser.json());
httpServer.use(bodyParser.text({
    type: 'application/x-ndjson'
   }));

httpServer.use((req,res)=>{
    proxy.web(req,res,{
        target:'http://kibana:5601'
    })
})
httpServer.set('port', 8083);
httpServer.listen(httpServer.get('port'), () => console.log(`httpServer for proxy started on port ${httpServer.get('port')}`));


proxy.on('proxyRes', function(proxyRes, req, res) {
    // console.log("---------proxyRes---event--------")
    // console.log(req)
    // console.log(req.method)
    // console.log("---------proxyRes---event--------")
    
    if(!res.finished){
        res.setHeader('Access-Control-Allow-Origin', 'http://192.168.28.169:8081')
        res.setHeader('Access-Control-Allow-Credentials', 'true')
        res.setHeader('Access-Control-Allow-Headers', 'user_sid')
        res.setHeader('Access-Control-Allow-Methods', 'GET')

        if(req.method=='OPTIONS'){
            res.statusCode = 200;
            res.end();
        }
    }
  });  
proxy.on('proxyReq', function(proxyReq, req, res) {
    // console.log("on proxyReq")
    // console.log(proxyReq.path)
    var cookies = proxyReq.getHeader('cookie')
    if(cookies){
        var cookieArray = cookies.split(";");
        cookieArray.forEach(element=>{
            if(element.indexOf('kibana_token')!=-1){
                var kibanaToken = element.split("=")[1].trim();
                var payload = base64decode(kibanaToken.split(".")[1])
                // console.log('payload**************************'+payload)
                if(proxyReq.path.indexOf("_bulk_get")!=-1){
                    jwt.verify(kibanaToken,'123456',(err,decoded)=>{
                        if(err){
                            res.statusCode = 400
                            res.statusMessage = "{'status':'token error'}"
                            res.end()
                            console.log("jwt verify error: "+err)
                        }
                        
                        var authorizedIdArray = decoded.permission.read

                        let requestId = req.body[0].id
                        if(req.body[0].type=='dashboard'){
                            if(!authorizedIdArray.includes(requestId)){
                                    console.log("unauthorized")
                                    console.log(req.body)
                                    res.statusCode = 401
                                    res.end()
                            }else{

                            }
                        }
                    })
                }
            }
        });
    }

    if(proxyReq.path.indexOf('stage-api/kibana')!=-1){
        proxyReq.path=proxyReq.path.replace('stage-api\/kibana\/','')
    }

    if(proxyReq.method!="GET" &&proxyReq.method!="OPTIONS"){
        // console.log(req.body)
        // if(proxyReq.getHeader('content-type').indexOf('application/json')!=-1){
            
           
        if(proxyReq.getHeader('content-type')&&proxyReq.getHeader('content-type').indexOf('application/json')!=-1){

            proxyReq.write(JSON.stringify(req.body))
        }else{
            console.log("not json")
            console.log(proxyReq.getHeader('content-type'))
            console.log(proxyReq.method)
            if(req.body) proxyReq.write(req.body)
        }
    }

    //get kibana_token from query string
    // var index = proxyReq.path.indexOf('kibana_token');
    // if(index!=-1){
    //     var kibana_token = proxyReq.path.substring(index).split('=')[1]

    //     res.setHeader('Set-Cookie','kibana_token='+kibana_token+';HttpOnly;Path=/;domain='+'192.168.28.169');
    //     console.log("check incomingMessage-----------------------------")
    //     console.log(req.headers)
    // }else{
        
    // }

  }); 

//
// Create your target server
//
