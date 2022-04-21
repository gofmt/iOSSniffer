package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/gofmt/iOSSniffer/pkg/frida"
	"github.com/gofmt/iOSSniffer/pkg/idevice"
	"github.com/gofmt/iOSSniffer/pkg/idevice/installation"
	"github.com/gofmt/iOSSniffer/pkg/idevice/pcap"
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

	conn, err := idevice.NewConn()
	if err != nil {
		fmt.Println("创建设备连接错误：", err)
		os.Exit(-1)
	}
	defer func(conn *idevice.Conn) {
		_ = conn.Close()
	}(conn)

	devices, err := conn.ListDevices()
	if err != nil {
		fmt.Println("获取iOS设备列表错误:", err)
		os.Exit(-1)
	}

	if len(devices) == 0 {
		fmt.Println("未找到iOS设备")
		os.Exit(-1)
	}

	device := devices[0]
	appClient, err := installation.NewClient(device.UDID)
	if err != nil {
		fmt.Println("创建安装服务客户端错误：", err)
		os.Exit(-1)
	}
	defer func(cli *installation.Client) {
		_ = cli.Close()
	}(appClient)

	apps, err := appClient.InstalledApps()
	if err != nil {
		fmt.Println("获取已安装应用列表错误：", err)
		os.Exit(-1)
	}

	fmt.Println("应用列表：")
	fmt.Println("--------------------------------------------------------------")
	for i, app := range apps {
		if app.CFBundleDisplayName != "" {
			fmt.Println(i, "\t|", app.CFBundleDisplayName, "["+app.CFBundleIdentifier+"]["+app.CFBundleExecutable+"]")
		}
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

	if idx > len(apps)-1 {
		fmt.Printf("'%d' 应用ID不存在\n", idx)
		os.Exit(-1)
	}

	name := apps[idx].CFBundleDisplayName
	fmt.Println("["+name+"]", "正在抓包,[CTRL+C]停止抓包...")

	bundleID := apps[idx].CFBundleIdentifier
	execName := apps[idx].CFBundleExecutable
	ctx, cancel := signal.NotifyContext(context.Background(), os.Kill, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGABRT)
	if *bTls {
		keyLogFile, err := os.Create(execName + ".keylog")
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

	pcapClient, err := pcap.NewClient(device.UDID)
	if err != nil {
		fmt.Println("创建PCAP客户端错误:", err)
		os.Exit(-1)
	}
	defer func(pcapClient *pcap.Client) {
		_ = pcapClient.Close()
	}(pcapClient)

	pcapFile, err := os.Create(name + ".pcap")
	if err != nil {
		fmt.Println("创建PCAP文件错误:", err)
		os.Exit(-1)
	}
	defer func(pcapFile *os.File) {
		_ = pcapFile.Close()
	}(pcapFile)

	go func() {
		<-ctx.Done()
		fmt.Println("正在停止抓包，封包数据回写有点慢，请等待几秒出现抓包结束提示...")
	}()

	err = pcapClient.ReadPacket(ctx, execName, pcapFile, func(data []byte) {
		fmt.Println(hex.Dump(data))
	})
	if err != nil {
		fmt.Println("读取网络封包错误:", err)
		os.Exit(-1)
	}

	cancel()

	// wireshark -r xxx.pcap -o "tls.keylog_file:./xxx.keylog"
	wiresharkParam := fmt.Sprintf(`wireshark -r %s.pcap -o "tls.keylog_file:./%s.keylog"`, name, execName)
	_ = ioutil.WriteFile("wireshark.sh", []byte(wiresharkParam), os.ModePerm)

	fmt.Println("["+name+"]", "抓包结束")
}
