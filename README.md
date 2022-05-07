## iOS抓包工具
* 简单，便捷，iOS设备插上USB在macOS或Linux上执行即可；
* 针对单个进程抓包，再也不怕抓包数据太多而难以分析；
* 保存为标准的pcap格式，结果用wireshark打开分析；
* 实验性支持TLS解密；

![image](iOSSniffer.gif)

## 使用方法
* TLS解密功能只需要iOS安装frida环境；
* 将iOS设备插入mac主机USB(目前只支持一台设备)；
* 执行 ./iOSSniffer 选择需要抓包的应用编号；
* 结束抓包后执行 ./wireshark.sh
> 如果需要TLS解密，使用 -t 参数

## 计划
- [ ] 增加pcap解析和浏览功能,用简单的方式查看封包;

## 编译
* 下载 [frida](https://github.com/frida/frida/releases) 开发包，复制 libfrida-core.a 到 pkg/frida 目录；
* 需要TLS解密时执行： go build -o iOSSniffer -tags frida ./cmd
* 无需TLS解密时执行： go build -o iOSSniffer ./cmd

## 交流
QQ群: 280090
