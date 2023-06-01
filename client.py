"""
Copyright (c) 2023 Gou Haoming
longPolling is licensed under Mulan PSL v2.
You can use this software according to the terms and conditions of the Mulan PSL v2. 
You may obtain a copy of Mulan PSL v2 at:
        http://license.coscl.org.cn/MulanPSL2 
THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.  
See the Mulan PSL v2 for more details.  
"""
import requests
import threading
import time
from typing import Callable,Any,Union,Literal
import logging
import rsa
class Client():
    def __init__(self,host:str,callBack:Callable[[bytes],Any],timeout:Union[int,float]=60,interval:Union[int,float]=1):
        """
        :param host: the url to connect to, it should be started with "http" or "https",and end without "/"
        :param callBack: the function to call after a new message is received
        :param timeout: the number of seconds, it should be same as the timeout in server
        :param interval: the number of seconds, how long to wait after a request
        """
        self.host = host
        self.callBack = callBack
        self.timeout = timeout
        self.interval = interval
        self.logger = logging.getLogger("Client")
        self.thread:Union[None,threading.Thread]=None
        self.state:Literal["running","stoped"]="stoped"
        self.key:Union[rsa.PrivateKey,None]=None
        self.id:Union[str,None]=None
    def logout(self)->None:
        if (self.key==None):
            self.logger.error("No login has been performed")
            raise LookupError("No login has been performed")
        try:
            retsult=requests.post(self.host+"/logout",json={
                "username":self.id,
                "key":self.key.save_pkcs1().decode("utf-8")
            })
            assert retsult.status_code==200
            self.state="stoped"
            self.key=None
            self.logger.info("logout successfully")
        except BaseException as err:
            raise
    def login(self,name)->bool:
        if self.key!=None:
            return False
        try:
            (public_key, private_key) = rsa.newkeys(512)
            retsult=requests.post(self.host+"/login",json={
                "username":name,
                "key": public_key.save_pkcs1().decode("utf-8")
            })
            if retsult.status_code==200:
                self.id=name
                self.key=private_key
                self.state="running"
                self.thread=threading.Thread(target=self._loop,daemon=True,name="Client")
                self.thread.start()
                self.logger.info("login successfully")
                return True
            if retsult.status_code==403:
                self.logger.warning("the server refused the login request")
                return False
            raise ConnectionError(retsult.status_code)
        except BaseException as err:
            self.logger.error(f"{err.__class__.__name__}:{err}")
            raise
    def _loop(self):
        checked="0"
        while True:
            if (self.state=="stoped"):
                self.thread=None
                return
            else :
                try:
                    retsult=requests.get(self.host+f"/{self.id}/listen",headers={"checked":checked},timeout=self.timeout)
                    
                except requests.exceptions.ReadTimeout:
                    checked = "0"
                else:
                    checked="1"
                    if (self.state=="stoped"):
                        self.thread=None
                        return
                    assert self.key!=None
                    self.callBack(rsa.decrypt(retsult.content,self.key))
            time.sleep(self.interval)
class BothwayClient(Client):
    def __init__(self,host:str,callBack:Callable[[bytes],Any],timeout:Union[int,float]=60,interval:Union[int,float]=1):
        """
        :param host: the url to connect to, it should be started with "http" or "https",and end without "/"
        :param callBack: the function to call after a new message is received
        :param timeout: the number of seconds, it should be same as the timeout in server
        :param interval: the number of seconds, how long to wait after a request
        """
        super().__init__(host,callBack,timeout,interval)
        self.pubKey:Union[rsa.PublicKey,None]=None
    def send(self,data:bytes):
        if (self.pubKey==None):
            self.logger.error("No login has been performed")
            raise LookupError("No login has been performed")
        data=rsa.encrypt(data,self.pubKey)
        retsult=requests.post(self.host+f"/{self.id}/send",data=data)
    def login(self,name)->bool:
        if self.key!=None:
            return False
        try:
            (public_key, private_key) = rsa.newkeys(1024)
            retsult=requests.post(self.host+"/login",json={
                "username":name,
                "key": public_key.save_pkcs1().decode("utf-8")
            })
            if retsult.status_code==200:
                self.id=name
                self.key=private_key
                self.pubKey=rsa.PublicKey.load_pkcs1(retsult.json()["key"].encode("utf-8"))
                self.state="running"
                self.thread=threading.Thread(target=self._loop,daemon=True,name="Client")
                self.thread.start()
                self.logger.info("login successfully")
                return True
            if retsult.status_code==403:
                self.logger.warning("the server refused the login request")
                return False
            raise ConnectionError(retsult.status_code)
        except BaseException as err:
            self.logger.error(f"{err.__class__.__name__}:{err}")
            raise