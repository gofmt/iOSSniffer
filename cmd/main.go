package main

import (
	"fmt"
	"strconv"

	"iOSSniffer/pkg/sniffer"

	"github.com/danielpaulus/go-ios/ios"
	"github.com/danielpaulus/go-ios/ios/installationproxy"
)

func main() {
	deviceList, err := ios.ListDevices()
	if err != nil {
		panic(err)
	}

	if len(deviceList.DeviceList) == 0 {
		panic("未找到 iPhone 设备")
	}

	entry := deviceList.DeviceList[0]
	conn, err := installationproxy.New(entry)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	userAppList, err := conn.BrowseUserApps()
	if err != nil {
		panic(err)
	}

	sysAppList, err := conn.BrowseSystemApps()
	if err != nil {
		panic(err)
	}

	appList := make([]installationproxy.AppInfo, 0)
	appList = append(appList, userAppList...)
	appList = append(appList, sysAppList...)

	fmt.Println("应用列表：")
	fmt.Println("--------------------------------------------------------------")

	for i, info := range appList {
		fmt.Println(i, "\t", info.CFBundleDisplayName, "["+info.CFBundleIdentifier+"]["+info.CFBundleExecutable+"]")
	}

	fmt.Println("--------------------------------------------------------------")
	fmt.Println("输入应用编号开始抓包：")
	var input string
	_, err = fmt.Scan(&input)
	if err != nil {
		panic(err)
	}

	idx, err := strconv.Atoi(input)
	if err != nil {
		panic(err)
	}

	name := appList[idx].CFBundleDisplayName
	fmt.Println("["+name+"]", "正在抓包...")

	execName := appList[idx].CFBundleExecutable
	if err := sniffer.StartSinffer(entry, execName, name+".pcap"); err != nil {
		panic(err)
	}

	fmt.Println("["+name+"]", "抓包结束")
}
