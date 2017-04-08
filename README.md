# Sgu DrCom Client 

### What's SguDrComClient?

**SguDrComClient** 是由 **[laijingwu](https://laijingwu.com)** 和 **[Steven-Zhou](https://github.com/Zhou-Haowei)** 联合为韶关学院特别编写的**第三方 DrCom 客户端**，适用于韶关学院西区丁香苑等接入电信网络且使用 DrCom 5.2.1(X) 客户端的学生宿舍，它依赖于 libpcap, pthread 库，可编译后运行于 *Linux*, *OpenWrt*。后续将继续适配 *Windows*, *MacOS*。

基于本核心重构的 *MacOS GUI* 版：[Zhou-Haowei/SguDrcomClientGUI](https://github.com/Zhou-Haowei/SguDrcomClientGUI)

Current Version: v1.0

### Configurate

配置文件 ( drcom.conf ) ：

```
#[config]
device=ens33			# 用于拨号的网卡
username=13110000000	# 内网认证账号
password=111111			# 内网认证密码
authserver_ip=192.168.127.129	# 认证服务器地址(固定)
udp_alive_port=61440	# 认证服务器通信端口(固定)
auto_login=0			# 是否断线重连(保留)
```

除了设置静态IP与绑定Mac网卡地址外，还需要为内网认证通信添加静态路由。在 Linux 终端中，执行以下命令：

```shell
sudo route add -net 192.168.0.0 netmask 255.255.0.0 gw 192.168.x.254
# x 为所设置的静态IP的第三组数字，且需要以管理员权限执行。
```

### Compile

Linux:

```shell
cd ./src/
make
sudo ./SguDrcom drcom.conf	# drcom.conf 为配置文件路径
```

**注意：**<u>最后一句执行必须使用管理权限，否则程序无权限打开对应网卡。</u>

**SguDrComClient** 依赖于：

> libpcap ( >= 1.5.3 )
>
> pthread

编译环境依赖于 **gcc、g++** 编译器，请确保已安装正确的编译器。

<u>Ubuntu 16.04 LTS（测试编译通过）</u>

### Special Thanks

**SguDrComClient** 的诞生离不开“巨人的肩膀”，特别是适配 DrCom 5.2.1 P版的，由 **Shindo** 编写的 **[EasyDrcom](https://github.com/coverxit/EasyDrcom)**。

此外，还要感谢 [**CuberL**](http://cuberl.com/2016/09/17/make-a-drcom-client-by-yourself/) 提供帮助。

### Special Attention

作者开源的初衷即是为了学习交流，严禁使用该源代码从事商业活动并从中谋取利益，如有违反，后果与作者无关。

### License

> Copyright (C) 2017 laijingwu & Steven-Zhou
>
> GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007
>
> 　　<http://fsf.org/>
>
> Everyone is permitted to copy and distribute verbatim copies of this license document, but changing it is not allowed.