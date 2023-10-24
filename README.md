# mini-sniffer

> 国科大网络攻防基础2023秋季课程的Lab1a

### 简介

基于QT6和Npcap实现的Sniffer，仿Wireshark页面，实现ICMP、ARP、UDP、TCP、DNS、SSL等协议的解析，实现了基本的数据包协议类型过滤

### 编程环境

Windows11、QT6.6.0、Npcap_SDK_1.12、Qmake

### 使用方法

1. 在官网安装QT6
2. 下载源码（不需要upload_homework文件夹，不需要额外下载Npcap）
3. 使用QT6打开项目，选择`mini-sniffer.pro`文件
4. 等待自动配置完成后点击左下角绿色小三角`运行`按钮，即可执行

5. 不是必须的一步，生成打包可执行文件，可以在没有QT的电脑上运行
   - 左下角选择为Release模型，默认是Debug，然后运行
   - 在项目文件夹的同级目录下会看到`build-XXXX-Release`命令的目录，将`build-XXXX-Release\release\mini-sniffer.exe`单独存放到另一个任意文件夹`D:\test\`
   - win11下搜索Qt，打开`QT 6.6.0(MinGW 11.2.0 64-bit)`，是个命令行界面（可能版本不尽相同）
   - 打开到之前的目录`cd D:\test\`
   - 执行打包命令`windeploy mini-sniffer.exe`，将该文件夹`D:\test\`压缩打包即可在没有QT的环境下执行

### 参考资料

- [QT 自制 wireshark (已完结)_哔哩哔哩_bilibili](https://www.bilibili.com/video/BV1mr4y127bV/?vd_source=39546d3139fc9fad1a66a5116d75d816)

- [djh-sudo/Network-capture: 网络抓包 (github.com)](https://github.com/djh-sudo/Network-capture)

- [likey99/mysniffer: 基于npcap的简单可视化网络嗅探器 (github.com)](https://github.com/likey99/mysniffer)