import tornado.ioloop
import tornado.web
import json
import os.path
import calendar
import datetime
import time
import jwt
from passlib.hash import bcrypt
import socket

global_secret = os.urandom(4096);
userCredentials = json.loads(open("passwd.json").read());

def is_authenticated(role):
  def decorator(func):
    def inner(*args, **kwargs):

      token = args[0].request.headers.get('Authorization');
      
      if( token is None ):
        args[0].set_status(403);
        args[0].write("Token is invalid. Please log in to obtain a valid token.");
        return;
      
      try:
        verifiedtoken = jwt.decode(token,global_secret);
      except jwt.ExpiredSignatureError:
        args[0].set_status(403);
        args[0].write("Token has expired. Please log in again.");
        return;
      except jwt.InvalidTokenError:
        args[0].set_status(403);
        args[0].write("Token is invalid. Please log in to obtain a valid token.");
        return;

      if(verifiedtoken["iat"] < int(userCredentials[verifiedtoken["usr"]]["lasttokenexpiry"])):
        args[0].set_status(403);
        args[0].write("This token has been explicitly expired. Please log in again.");
        return;

      if (verifiedtoken["role"] != role and role is not None):
        args[0].set_status(403);
        args[0].write("User does not have permission to access this page.");
        return;

      kwargs["token"] = verifiedtoken;

      return func(*args, **kwargs);
    return inner;
  return decorator;

class MainHandler(tornado.web.RequestHandler):

  def post(self):
    
    if self.request.path == "/api/dns":
      self.getDNS();
      return;
    
    if self.request.path == "/api/login":
      self.getToken();
      return;
    
    self.set_status(400);
    self.write("Bad request");

  @is_authenticated("user")
  def getDNS(self, token=None):
    domain = json.loads(self.request.body.decode('utf-8'))['domain'];
    self.set_status(200);
    self.write(socket.gethostbyname(domain));
    return;

  def getToken(self):
    userCredentials = json.loads(open("passwd.json").read());
    req = self.request.body.decode('utf-8');
    username = json.loads(req)["username"];
    password = json.loads(req)["password"];
    if username in userCredentials.keys():
      if bcrypt.verify( password, userCredentials[username]["password"]):
        payload = {
          'usr': username,
          'role': userCredentials[username]["role"],
          'iss': 'http://dns.danshick.net',
          'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1),
          'iat': datetime.datetime.utcnow()
        };
        new_token = jwt.encode(payload, global_secret, 'HS512');
        self.set_status(200);
        self.write(new_token);
        return;
      else:
        self.set_status(403);
        self.write("The password you entered is incorrect.");
        return;
    else:
      self.set_status(403);
      self.write("Specified username does not yet exist.");
      return;
    self.set_status(400);
    self.write("Bad request");

application = tornado.web.Application([
    (r"/api/?.*", MainHandler)
]);

application.listen(80)
tornado.ioloop.IOLoop.instance().start()
