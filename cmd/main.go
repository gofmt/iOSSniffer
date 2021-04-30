package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"

	"iOSSniffer/pkg/frida"
	"iOSSniffer/pkg/sniffer"

	"github.com/danielpaulus/go-ios/ios"
	"github.com/danielpaulus/go-ios/ios/installationproxy"
)

const (
	fridaScript = `try {
  Module.ensureInitialized("libboringssl.dylib");
} catch(err) {
  Module.load("libboringssl.dylib");
}
if (ObjC.available) {
  setImmediate(function () {
    const p = Module.findExportByName('CoreFoundation', 'kCFCoreFoundationVersionNumber');
    const version = Memory.readDouble(p)
    var CALLBACK_OFFSET = 0x2A8; // 0x2C8
    if (version >= 1751.108) {
      CALLBACK_OFFSET = 0x2B8;
    }
    function key_logger(ssl, line) {
      console.log(new NativePointer(line).readCString());
    }
    var key_log_callback = new NativeCallback(key_logger, 'void', ['pointer', 'pointer']);
    var SSL_CTX_set_info_callback = Module.findExportByName("libboringssl.dylib", "SSL_CTX_set_info_callback");
    Interceptor.attach(SSL_CTX_set_info_callback, {
      onEnter: function (args) {
        var ssl = new NativePointer(args[0]);
        var callback = new NativePointer(ssl).add(CALLBACK_OFFSET);

        callback.writePointer(key_log_callback);
      }
    });
  });
}`
)

var (
	bTls = flag.Bool("t", false, "启用TLS解密")
)

func main() {
	flag.Parse()

	deviceList, err := ios.ListDevices()
	if err != nil {
		fmt.Println("获取iOS设备列表错误:", err)
		os.Exit(-1)
	}

	if len(deviceList.DeviceList) == 0 {
		fmt.Println("未找到iOS设备")
		os.Exit(-1)
	}

	entry := deviceList.DeviceList[0]
	conn, err := installationproxy.New(entry)
	if err != nil {
		fmt.Println("连接服务失败：", err)
		os.Exit(-1)
	}
	defer conn.Close()

	userAppList, err := conn.BrowseUserApps()
	if err != nil {
		fmt.Println("获取用户应用列表错误：", err)
		os.Exit(-1)
	}

	sysAppList, err := conn.BrowseSystemApps()
	if err != nil {
		fmt.Println("获取系统应用列表错误：", err)
		os.Exit(-1)
	}

	appList := make([]installationproxy.AppInfo, 0)
	appList = append(appList, userAppList...)
	appList = append(appList, sysAppList...)

	fmt.Println("应用列表：")
	fmt.Println("--------------------------------------------------------------")

	for i, info := range appList {
		fmt.Println(i, "\t|", info.CFBundleDisplayName, "["+info.CFBundleIdentifier+"]["+info.CFBundleExecutable+"]")
	}

	fmt.Println("--------------------------------------------------------------")
	fmt.Println("输入应用编号开始抓包：")
	var input string
	_, err = fmt.Scan(&input)
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}

	idx, err := strconv.Atoi(input)
	if err != nil {
		fmt.Printf("'%s' 不是正确的应用ID\n", input)
		os.Exit(-1)
	}

	if idx > len(appList)-1 {
		fmt.Printf("'%d' 应用ID不存在\n", idx)
		os.Exit(-1)
	}

	name := appList[idx].CFBundleDisplayName
	fmt.Println("["+name+"]", "正在抓包...")

	bundleID := appList[idx].CFBundleIdentifier
	execName := appList[idx].CFBundleExecutable
	ctx, cancel := context.WithCancel(context.Background())
	if *bTls {
		keyLogFile, err := os.OpenFile(execName+".keylog", os.O_CREATE|os.O_WRONLY, 0666)
		if err != nil {
			fmt.Println("创建KEYLOG文件错误:", err)
			os.Exit(-1)
		}
		defer func() {
			_ = keyLogFile.Close()
		}()

		go func() {
			if err := frida.StartFrida(ctx, keyLogFile, bundleID, fridaScript); err != nil {
				fmt.Println("Frida 错误:", err)
				os.Exit(-1)
			}
		}()
	}

	if err := sniffer.StartSinffer(entry, execName, name+".pcap"); err != nil {
		fmt.Println("抓包错误：", err)
		os.Exit(-1)
	}

	cancel()

	// wireshark -r xxx.pcap -o "tls.keylog_file:./xxx.keylog"
	wiresharkParam := fmt.Sprintf(`wireshark -r %s.pcap -o "tls.keylog_file:./%s.keylog"`, name, execName)
	_ = ioutil.WriteFile("wireshark.sh", []byte(wiresharkParam), os.ModePerm)

	fmt.Println("["+name+"]", "抓包结束")
}
