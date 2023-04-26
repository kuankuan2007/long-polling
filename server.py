import flask
import threading
import time
import json
from typing import Any,Union,Literal,Dict,Callable,List
import logging
import rsa
import random
def _randString():
    return "".join(random.choices(["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v","w", "x", "y", "z",
                    "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V","W", "X", "Y", "Z",
                    "1","2","3","4","5","6","7","8","9","0"],k=random.randint(10,100)))
class Server:
    def __init__(self,host:Union[str,None]=None,port:Union[int,None]=None,timeout:int=60,name:str='Server',login:Union[None,Callable[[str],Any]]=None,logout:Union[None,Callable[[str],Any]]=None):
        """
        :param host:the host to listen on
        :param port:the port to listen on
        :param timeout: the number of seconds, it should be same as the timeout in client
        :param name: the name of the server. it can be changed at any time.
        :param login: it will be caller after a new user is login successfully
        :param logout: it will be caller after a user is logout successfully
        """
        self.app = flask.Flask(name)
        self.logger = logging.getLogger(name)
        self.host = host
        self.port = port
        self.keys:Dict[str,rsa.PublicKey]={}
        self.loginCallBack=login
        self.logoutCallBack=logout
        self.timeout = timeout
        self.messages:Dict[str,List[bytes]] = {}
        
        
        @self.app.route("/<user>/listen",methods=["GET"])
        def main(user):
            start=time.time()
            if flask.request.headers.get("checked","0")!="0":
                del self.messages[user][0]
            while True:
                if (user not in self.keys):
                    return "unregistered",403
                if (time.time()-start)>=self.timeout:
                    return "timeout",500
                if (self.messages.get(user,[])):
                    return rsa.encrypt(self.messages[user][0],self.keys[user]),200
                time.sleep(1)
            
        @self.app.route("/login",methods=["POST"])
        def doLogin():
            try:
                now=json.loads(flask.request.stream.read().decode("utf-8","target"))
            except:
                return "decode error",400
            if (all([i in now for i in ["username","key"]])):
                if (now["username"] in self.keys):
                    return "duplicate user name",403
                self.keys[now["username"]]=rsa.PublicKey.load_pkcs1(now["key"].encode("utf-8"))
                if (self.loginCallBack):
                    self.loginCallBack(now["username"])
                
                return "succeed",200
            else:
                return "insufficient",400
        @self.app.route("/logout",methods=["POST"])
        def doLogout():
            try:
                now=json.loads(flask.request.stream.read().decode("utf-8","target"))
            except:
                return "decode error",400
            if (all([i in now for i in ["username","key"]])):
                if (now["username"] not in self.keys):
                    return "unregistered",400
                test=_randString()
                try:
                    assert rsa.decrypt(rsa.encrypt(test.encode("utf-8"),self.keys[now["username"]]),rsa.PrivateKey.load_pkcs1(now["key"].encode("utf-8")))==test.encode("utf-8")
                    del self.keys[now["username"]]
                    if (self.logoutCallBack):
                        self.logoutCallBack(now["username"])
                    return "succeed",200
                except:
                    return "key error",403
            else:
                return "insufficient",400
        
        self.logger.info("start server")
        self.thread = threading.Thread(target=self._start,daemon=True)
        self.thread.start()
    def _start(self):
        self.app.run(self.host,self.port,threaded=True)
    def send(self,user:str,message:Union[dict,list,bytes])->None:
        """
        :param user: username
        :param message: message to send to user,must be bytes-like object or dict or list
        """
        if type(message)!=bytes:
            message = json.dumps(message).encode("utf-8")
        if (user not in self.messages):
            self.messages[user]=[]
        self.messages[user].append(message)
        self.logger.info("new message sent to user "+user)