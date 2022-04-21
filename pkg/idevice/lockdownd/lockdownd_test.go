package lockdownd

import (
	"testing"

	"github.com/gofmt/iOSSniffer/pkg/idevice"
)

func TestLockdowndClient_GetValues(t *testing.T) {
	conn, err := idevice.NewConn()
	if err != nil {
		t.Fatal(err)
	}
	defer func(conn *idevice.Conn) {
		_ = conn.Close()
	}(conn)

	devices, err := conn.ListDevices()
	if err != nil {
		t.Fatal(err)
	}

	for _, device := range devices {
		cli, err := NewClient(device.UDID)
		if err != nil {
			t.Fatal(err)
		}
		values, err := cli.GetValues()
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%#v", values)
		cli.Close()
	}
}
