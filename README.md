## iOS抓包工具
* 简单，便捷，设备插上USB在mac上执行即可；
* 针对单个进程抓包，再也不怕抓包数据太多而难以分析；
* 保存为标准的pcap格式，结果用wireshark打开分析；

![image](iOSSniffer.gif)

## 使用方法
* mac主机和iOS都需要安装frida环境；
* 将iOS设备插入mac主机USB(目前只支持一台设备)；
* 执行 ./iOSSniffer 选择需要抓包的应用编号；
* 结束抓包后执行 ./wireshark.sh

## 计划
- [x] 增加TLS解密功能;
- [ ] 增加pcap解析和浏览功能,用简单的方式查看封包;