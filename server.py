"""
Copyright (c) 2023 Gou Haoming
longPolling is licensed under Mulan PSL v2.
You can use this software according to the terms and conditions of the Mulan PSL v2. 
You may obtain a copy of Mulan PSL v2 at:
        http://license.coscl.org.cn/MulanPSL2 
THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.  
See the Mulan PSL v2 for more details.  
"""
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
    def __init__(self,host:Union[str,None]=None,port:Union[int,None]=None,timeout:int=60,name:str='Server',login:Union[None,Callable[[Any,str],Any]]=None,logout:Union[None,Callable[[Any,str],Any]]=None,threaded:bool=True,started:bool=True,offLine:Union[float,int,None]=None):
        """
        :param host:the host to listen on
        :param port:the port to listen on
        :param timeout: the number of seconds, it should be same as the timeout in client
        :param name: the name of the server. it can be changed at any time.
        :param login: it will be caller after a new user is login successfully
        :param logout: it will be caller after a user is logout successfully
        :param threaded: Whether to run in a new thread
        :param started: Whether to start the server
        :param offLine: How long there is no activity determines whether the login is invalid
        """
        self.app = flask.Flask(name)
        self.logger = logging.getLogger(name)
        self.host = host
        self.port = port
        self.users:Dict[str,Dict[str,Any]]={}
        self.loginCallBack=login
        self.logoutCallBack=logout
        self.timeout = timeout
        self.messages:Dict[str,List[bytes]] = {}
        self.threaded=threaded
        self.offLine=offLine
        @self.app.route("/<user>/listen",methods=["GET"])
        def main(user):
            return self.main(user)
        
        @self.app.route("/login",methods=["POST"])
        def doLogin():
            return self.doLogin()
        
        @self.app.route("/logout",methods=["POST"])
        def doLogout():
            return self.doLogout()
        if started:
            self.start()
        
    def doLogin(self):
        try:
            now=flask.request.json
            assert type(now)==dict
        except:
            return "decode error",400
        if (all([i in now for i in ["username","key"]])):
            if (now["username"] in self.users and self.offLine!=None and (time.time()-self.users[now["username"]]["last_login"])<=self.offLine):
                return "duplicate user name",403
            self.users[now["username"]]={
                "key":rsa.PublicKey.load_pkcs1(now["key"].encode("utf-8")),
                "last_login":time.time()
            }
            if (self.loginCallBack):
                self.loginCallBack(self,now["username"])
            return "succeed",200
        else:
            return "insufficient",400
    def doLogout(self):
        try:
            now=flask.request.json
            assert type(now)==dict
        except:
            return "decode error",400
        if (all([i in now for i in ["username","key"]])):
            if (now["username"] not in self.users):
                return "unregistered",400
            test=_randString()
            try:
                assert rsa.decrypt(rsa.encrypt(test.encode("utf-8"),self.users[now["username"]]["key"]),rsa.PrivateKey.load_pkcs1(now["key"].encode("utf-8")))==test.encode("utf-8")
                del self.users[now["username"]]
                if (self.logoutCallBack):
                    self.logoutCallBack(self,now["username"])
                return "succeed",200
            except:
                return "key error",403
        else:
            return "insufficient",400
    def main(self,user):
        start=time.time()
        self.users[user]["last_login"]=time.time()
        if flask.request.headers.get("checked","0")!="0":
            del self.messages[user][0]
        while True:
            if (user not in self.users):
                return "unregistered",403
            if (time.time()-start)>=self.timeout:
                return "timeout",500
            if (self.messages.get(user,[])):
                return rsa.encrypt(self.messages[user][0],self.users[user]["key"]),200
            time.sleep(1)
    def start(self):
        self.logger.info("start server")
        if self.threaded:
            self.thread = threading.Thread(target=self._start,daemon=True)
            self.thread.start()
        else:
            self._start()
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
class BothwayServer(Server):
    def __init__(self,host:Union[str,None]=None,port:Union[int,None]=None,timeout:int=60,name:str='Server',login:Union[None,Callable[[Server,str],Any]]=None,logout:Union[None,Callable[[Server,str],Any]]=None,receive:Union[None,Callable[[Server,str,bytes],Any]]=None,threaded:bool=True,started:bool=True,offLine:Union[float,int,None]=None):
        """
        :param host:the host to listen on
        :param port:the port to listen on
        :param timeout: the number of seconds, it should be same as the timeout in client
        :param name: the name of the server. it can be changed at any time.
        :param login: it will be caller after a new user is login successfully
        :param logout: it will be caller after a user is logout successfully
        :param receive: it will be caller after receive a message
        :param threaded: Whether to run in a new thread
        :param started: Whether to start the server
        :param offLine: How long there is no activity determines whether the login is invalid
        """
        super().__init__(host,port,timeout,name,login,logout,threaded,False,offLine)
        self.receive=receive
        @self.app.route("/<user>/send",methods=["POST"])
        def doListen(user):
            return self.doListen(user,flask.request.stream.read())
        if started:
            self.start()
    def doListen(self,user:str,data:bytes):
        try:
            data=rsa.decrypt(data,self.users[user]["priKey"])
        except:
            return "keyError",403
        if (self.receive):
            self.users[user]["last_login"]=time.time()
            self.receive(self,user,data)
        return "success"
    def doLogin(self):
        retsult=super().doLogin()
        if(retsult[1]==200):
            try:
                now=flask.request.json
                assert type(now)==dict
            except:
                return "decode error",400
            (public_key, private_key) = rsa.newkeys(1024)
            self.users[now["username"]]["priKey"]=private_key
            return json.dumps({
                "key":public_key.save_pkcs1().decode("utf-8")
            }),200
        return retsult