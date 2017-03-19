# SguDrcomClient 

### What's SguDrcomClient?

**SguDrcomClient** 是由 **[laijingwu](https://laijingwu.com)** 和 **[Steven-Zhou](https://github.com/Zhou-Haowei)** 联合为韶关学院特别编写的**第三方 DrCom 客户端**，适用于韶关学院西区丁香苑等接入电信网络且使用DrCom 5.2.1(X)客户端的学生宿舍，它依赖于libpcap, pthread库，可编译后运行于 *Linux*。暂时只适配 *Linux*，后续将继续适配 *Windows, MacOS, OpenWrt*。

### Todo List

- [ ] 30分钟掉线且无法上线
- [ ] 在其他机器上测试 UDP40_2 无法发送
- [x] ~~返回长度为 272 的 UDP40 包未发送~~
- [ ] 掉线后 socket 使用外网 IP 发送 udp
- [ ] 偶尔出现 Start 后无返回包导致阻塞进而无法上线
- [ ] 针对其他平台进行适配

### Special Thanks

**SguDrcomClient** 的诞生离不开“巨人的肩膀”，特别是适配 DrCom 5.2.1 P版的，由 **Shindo** 编写的 **[EasyDrcom](https://github.com/coverxit/EasyDrcom)**。

此外，还要感谢 [**CuberL**](http://cuberl.com/2016/09/17/make-a-drcom-client-by-yourself/) 博客提供帮助。

### Special Attention

作者开源的初衷即是为了学习交流，严禁使用该源代码从事商业活动并从中谋取利益，如有违反，后果与作者无关。

### License

> Copyright (C) 2017 laijingwu & Steven-Zhou
>
> GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007
>
> ​	<http://fsf.org/>
>
> Everyone is permitted to copy and distribute verbatim copies of this license document, but changing it is not allowed.