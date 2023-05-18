# 长轮询(longPolling)

```bash
pip install longPolling 
```

## 客户端

### 单向传输

```python
import longPolling
example=longPolling.client.Client(url, callback)
example.login(uername)
```

### 双向传输

```python
import longPolling
example=longPolling.client.BothwayClient(url, callback)
example.login(uername)
example.send(data)
```

## 服务端

### 单向传输

```python
import longPolling
example=longPolling.server.Server(host,port)
example.send(username,message)
```

### 双向传输

```python
import longPolling
example=longPolling.server.BothwayServer(host,port,callback)
example.send(username,message)
```

## 关于作者

作者主页[宽宽2007](https://kuankuan2007.gitee.io "作者主页")

pypi[longPolling    · PyPI](https://pypi.org/project/longPolling/)

本项目在[苟浩铭/长轮询 (gitee.com)](https://gitee.com/kuankuan2007/long-polling)上开源

帮助文档参见[宽宽的帮助文档](https://kuankuan2007.gitee.io/docs/long-polling)
