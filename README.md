## 项目简介

本项目是由C实现的Linux的轻量级多线程HTTP服务器，采用高效的Reactor事件分发模式，支持高并发的http请求。

## 系统环境

- 系统：Ubuntu20.04
- 编译器：gcc 9.3.0

## 项目构建方法

```c
git init
git clone https://github.com/ChenSaoki/Tinyhttpd_with_Reactor_epoll.git
make
./httpd
```

## 注意事项

- 默认端口为1735

- HTTP请求页面为websiti目录下的.html与.cgi后缀文件(可以手动添加)

- post.html 以及 post.cgi需要一定的权限才可以执行。

  - ```shell
    cd websiti
    sudo chmod 600 index.html
    sudo chmod 600 post.html
    sudo chmod +X post.cgi
    ```

  

## 框架



## 参考