//decoded
const { verify } = require("jsonwebtoken");
require('dotenv').config();

const isAuth = (req) => {
  //give us token
  const authorization = req.get("authorization");
  
  if(!authorization) throw new Error("you need to login");
  //'Bearer token'
  //token 부분만 가져오기
  const token = authorization.split(" ")[1];
  const {userId} = verify(token, process.env.ACCESS_TOKEN_SECRET);

  return userId;
}

module.exports = {
  isAuth
}