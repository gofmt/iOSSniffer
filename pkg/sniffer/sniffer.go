package sniffer

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/danielpaulus/go-ios/ios"
	"golang.org/x/xerrors"
	"howett.net/plist"
)

const (
	TcpdumpMagic     = 0xa1b2c3d4
	PcapVersionMajor = 2
	PcapVersionMinor = 4
	DltEn10mb        = 1
)

type PcapGlobalHeader struct {
	MagicNumber  uint32
	VersionMajor uint16
	VersionMinor uint16
	Thiszone     int32
	Sigfigs      uint32
	Snaplen      uint32
	Network      uint32
}

type PcapPacketHeader struct {
	Timestamp1 uint32
	Timestamp2 uint32
	CapLen     uint32
	Len        uint32
}

type IOSPacketHeader struct {
	HdrLength      uint32
	Version        uint8
	Length         uint32
	Type           uint8
	Unit           uint16
	IO             uint8
	ProtocolFamily uint32
	FramePreLength uint32
	FramePstLength uint32
	IFName         [16]byte
	Pid            uint32
	ProcName       [17]byte
	Unknown        uint32
	Pid2           uint32
	ProcName2      [17]byte
	Unknown2       [8]byte
}

func StartSinffer(entry ios.DeviceEntry, procName, pcapPath string) error {
	intf, err := ios.ConnectToService(entry, "com.apple.pcapd")
	if err != nil {
		return xerrors.Errorf("连接抓包服务错误: %w", err)
	}
	defer intf.Close()

	f, err := os.OpenFile(pcapPath, os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		return xerrors.Errorf("创建PCAP文件错误: %w", err)
	}

	wr := bufio.NewWriter(f)
	header := PcapGlobalHeader{
		MagicNumber:  TcpdumpMagic,
		VersionMajor: PcapVersionMajor,
		VersionMinor: PcapVersionMinor,
		Thiszone:     0,
		Sigfigs:      0,
		Snaplen:      uint32(65535),
		Network:      uint32(DltEn10mb),
	}

	if err = binary.Write(wr, binary.LittleEndian, header); err != nil {
		return xerrors.Errorf("PCAP全局包头写入失败失败: %w", err)
	}

	defer func() {
		_ = wr.Flush()
		_ = f.Close()
	}()

	pListCodec := ios.NewPlistCodec()
	go func() {
		for {
			bs, err := pListCodec.Decode(intf.Reader())
			if err != nil {
				fmt.Println("iOS解包错误: " + err.Error())
				return
			}

			_, err = plist.Unmarshal(bs, &bs)
			if err != nil {
				fmt.Println("iOS包系列化错误: " + err.Error())
				return
			}

			buf := bytes.NewBuffer(bs)
			var hdr IOSPacketHeader
			if err = binary.Read(buf, binary.BigEndian, &hdr); err != nil {
				fmt.Println("iOS包头读取失败: " + err.Error())
				return
			}

			pName := string(hdr.ProcName[:])
			pName2 := string(hdr.ProcName2[:])
			if !strings.HasPrefix(pName, procName) && !strings.HasPrefix(pName2, procName) {
				continue
			}

			go func() {
				fmt.Println(hex.Dump(bs))
			}()

			pcapPacketHeader := PcapPacketHeader{
				Timestamp1: uint32(time.Now().Unix()),
				Timestamp2: uint32(time.Now().UnixNano() / 1e6),
				CapLen:     hdr.Length,
				Len:        hdr.Length,
			}

			if err = binary.Write(wr, binary.LittleEndian, pcapPacketHeader); err != nil {
				fmt.Println("PCAP包头写入失败失败: " + err.Error())
				return
			}

			if hdr.FramePreLength == 0 {
				ext := []byte{0xbe, 0xfe, 0xbe, 0xfe, 0xbe, 0xfe, 0xbe, 0xfe, 0xbe, 0xfe, 0xbe, 0xfe, 0x08, 0x00}
				body := append(ext, bs[hdr.HdrLength:]...)
				err = binary.Write(wr, binary.LittleEndian, body)
			} else {
				err = binary.Write(wr, binary.LittleEndian, bs[hdr.HdrLength:])
			}

			if err != nil {
				fmt.Println("写入PCAP文件错误：", err)
				return
			}

			_ = wr.Flush()

		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, os.Kill, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGHUP)
	<-quit

	return nil
}
