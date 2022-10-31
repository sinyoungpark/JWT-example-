require("dotenv").config();
const express = require("express");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const { verify } = require("jsonwebtoken");
const { hash, compare } = require("bcryptjs");
const { createAccessToken, createRefreshToken, sendAccessToken, sendRefreshToken } = require("./tokens");

const { fakeDB } = require("./fakeDB");
const { isAuth } = require("./isAuth");

//1. register a user
//2. loogin a user
//3. logout a user
//4. setup a protected route
//5. get a new accesstoken with a refrech token

const server = express();

//user express middleware for easier cookie handling
server.use(cookieParser());

//cors setting 
server.use(cors({
  origin : "http://localhost:3000",
  credentials : true,
}));

//needed to be able to need body data
server.use(express.json());//to support json-encoded body
server.use(express.urlencoded({
  extended : true
})); //support url-encoded body


//1. register a user
server.post('/register', async(req,res) => {
  const {email, password} = req.body;
  
  try{
    //1. check if the user exist
    const user = fakeDB.find(user => user.email === email);
    if(user) throw new Error("user already exist");
    //2. if not user exist, hash the password
    const hashedPassword = await hash(password, 10);
    //3. insert the user in "database"
    fakeDB.push({
      id : fakeDB.length, 
      email,
      password : hashedPassword
    });
    res.send({message : "user created"});
    console.log(fakeDB);
  }
  catch(e){
    res.send({
      error : `${e.message}`
    });
  }
});


//2. login a user
server.post("/login", async(req,res) => {
  const {email, password} = req.body;
  
  try{
    //1. find user in "database". if not exist res error
    const user = fakeDB.find(user => user.email);
    if(!user) throw new Error("user doesn't exist");
    //2. compare crypted password and see if checks out. send error if not 
    const valid = await compare(password, user.password);
    if(!valid) throw new Error("password not correct");
    //3. create refresh- and accesstoken
    const accesstoken = createAccessToken(user.id);
    const refreshtoken = createRefreshToken(user.id);
    //4. put the refreshtoken in the database
    user.refreshtoken = refreshtoken;
    console.log(fakeDB);
    //5. send token. refreshtoken as a cookie and access-token send a regular response
    sendRefreshToken(res, refreshtoken);
    sendAccessToken(req, res, accesstoken);

  }
  catch(e){
    res.send({
      error : `${e.message}`,
    })
  }
});

//3. logout a user 
server.post("/logout", async(_req,res) => {
  res.clearCookie("refreshtoken",{
    path : "/refresh_token"
  });
  return res.send({
    message : "logged out",
  });
});

//4. protected route : authorization with json token
server.post("/protected", async (req, res) => {
  try{
    const userId = isAuth(req);
    if(userId !== null){
      res.send({
        data : 'this is protected data'
      });
    }
  }
  catch(e){
    res.send({
      error : `${e.message}`
    })
  }
});

//get a new access token with a refresh token
server.post("/refresh_token", (req,res) => {
  const token = req.cookies.refreshtoken;
  //if we don't have a token in out request
  if(!token) return res.send({
    accesstoken : ''
  });
  //we have a token, let's verify it!
  let payload = null;
  try{
    payload = verify(token, process.env.REFRESH_TOKEN_SECRET);
  }
  catch(e){
    return res.send({
      accesstoken : ''
    });
  }
  //token is valid, check if user exist 
  const user = fakeDB.find(user => user.id === payload.userId);
  if(!user) return res.send({accesstoken : ""});
  //user exist, check if refreshtoken exist on user
  if(user.refreshtoken !== token){
    return res.send({accesstoken : ""});
  }
  //token exist, create new Refresh and access token
  const accesstoken = createAccessToken(user.id);
  const refreshtoken = createRefreshToken(user.id);

  user.refreshtoken = refreshtoken;
  //all good to go, send new refreshtoken and accesstoken
  sendRefreshToken(res, refreshtoken);
  return res.send({accesstoken});
});

server.listen(process.env.PORT, () => {
  console.log(`server listening on port ${process.env.PORT}`);
});