# DNS-Monitor
2018年学习前端之练习项目——**DNS请求监视器**
**目的：**
记录和展示我自己电脑上所有的DNS请求行为

## 平台支持
OSX、Python2、Tornado
## 
## 配置文件libs/config.ini

```
[proxyserver] Web Server配置项
listen_ip=127.0.0.1
listen_port=9000
username=admin
password=123456
[database] # 数据库配置项
ip=127.0.0.1
port=3306
username=root
password=root
dbname=PassiveDNS
```
## 启动：
```
python run.py
```
## 使用
访问: http://127.0.0.1:9000/ 
登录: 账号密码默认为：admin/123456
## 有问题欢迎提issues
虽然我也不一定能及时看见
