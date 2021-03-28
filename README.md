## 项目简介

本项目是由C实现的web服务器，采用高效的Reactor事件分发模式，支持高并发的http请求。

## 系统环境

- 系统：Ubuntu20.04
- 编译器：gcc 9.3.0



## 项目构建方法

```c
git init
git clone https://github.com/chensaoki/webServer.git
make
./httpd
```

## 注意事项

- 端口配置在httpd.cpp 默认为1735

- HTTP请求页面为websiti目录下的.html与.cgi后缀文件(可以手动添加)