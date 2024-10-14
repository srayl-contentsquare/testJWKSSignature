var jose = require ('node-jose');
var JWK = jose.JWK;
var jsonwebtoken = require("jsonwebtoken");
var jwksClient = require("jwks-rsa");
var client = jwksClient({jwksUri:"https://uxanalyser.zendesk.com/api/v2/help_center/integration/keys"});
var crypto = require("crypto");
var axios = require("axios");
var dotenv = require("dotenv");

dotenv.config();

var JwtPayload = jsonwebtoken.JwtPayload;
var TokenExpiredError = jsonwebtoken.TokenExpiredError;
var verify = jsonwebtoken.verify;
 
  //I've been manually grabbing the help center token while logged in from https://support.contentsquare.com/api/v2/help_center/integration/token and pasting it here. You should also be able to just grab it using ZD basic authentication/api key. It's good for a few minutes usually.
  var token = "PASTE TOKEN HERE";
  var options = {algorithms:"RS256"};

async function test () {
    try {
        let response = await axios.get("https://uxanalyser.zendesk.com/api/v2/help_center/integration/keys")
        await jose.JWK.asKey(response.data.keys[0]).then(
          async function(result){
            await jose.JWS.createVerify(result).verify(token).then(
              function(result){
                let payload = JSON.parse(result.payload.toString());
                console.log("expiration: " + payload.exp * 1000);
                console.log("now: " + Date.now());
                if ((payload.exp * 1000) < Date.now()) {
                  console.log("token is expired");
                } else {
                  console.log("token validated");
                  const token = jsonwebtoken.sign({
                    scope: 'user',
                    name: payload.name,
                    email: payload.email,
                    external_id: payload.email
                  }, process.env.SDK_TOKEN_SECRET, {header: {kid: process.env.SDK_KID	}});
                  console.log("SDK token: " + token)
                }
              }
            )
          });
    } catch (e) {
        console.log(e);
    }
}

test();