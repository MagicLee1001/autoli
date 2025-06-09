### 程序使用说明

星辰模块的使用，分为两部分，服务端和客户端。

服务端用来监听连接上来的板卡，必要时发送告警。

客户端负责在板卡和服务端之间转发，它与服务端之间保持一个心跳。

#### 服务端的使用

略 todo 待补充

#### 客户端的使用
客户端上需要运行两个不同的程序，一个负责与服务端心跳，一个在板卡和服务端之间转发；
前者使用的是这里的 stars_client.py 文件，后者使用的是 tool/tcp_agent/forward_ports.py 文件。

##### stars_client 的使用
这个代码需要使用同级的 stars_client.json 文件作为配置文件。

其中，要配置服务端的地址和端口，调试时可以使用本地，实际使用的时候改为用户实际使用的(serverAddress 以及 serverPort)。

#### forward 的使用
forward 目前没有发现需要配置什么，一边开发测试一边补充。

#### 两者一起使用的方法
两者可以分开启动，不过实际使用时，为了方便，是编译成 exe 使用的。

在本仓库的依赖中已经声明了要安装的 pyinstaller 版本。

使用 pyinstaller 直接编译就可以，不要改动编译出来的产物名字。

编译完毕后，需要将两个 exe，拷贝到相关的位置，同时记得拷贝 config 文件。

启动时，自己在同级放一个 bat 脚本，内容如下：

```bat
@echo off
if "%1"=="h" goto begin
start mshta vbscript:createobject("wscript.shell").run("""%~nx0"" h",0)(window.close)&&exit
:begin
start /B forward_ports.exe
sleep 2
start /B stars_client.exe
```

上面代码负责将两个编译好的 exe 作为后台进程启动。理论上是足够了。
