package main

import (
	"fmt"
	"os"
	"strconv"

	"iOSSniffer/pkg/sniffer"

	"github.com/danielpaulus/go-ios/ios"
	"github.com/danielpaulus/go-ios/ios/installationproxy"
)

func main() {
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

	execName := appList[idx].CFBundleExecutable
	if err := sniffer.StartSinffer(entry, execName, name+".pcap"); err != nil {
		fmt.Println("抓包错误：", err)
		os.Exit(-1)
	}

	fmt.Println("["+name+"]", "抓包结束")
}
