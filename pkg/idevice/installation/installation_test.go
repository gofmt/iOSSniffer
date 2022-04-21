package installation

import (
	"testing"

	"github.com/gofmt/iOSSniffer/pkg/idevice"
)

func TestClient_Lookup(t *testing.T) {
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

		exePath, err := cli.LookupExePath("me.ele.ios.eleme")
		if err != nil {
			t.Fatal(err)
		}
		t.Log(exePath)

		container, err := cli.LookupContainer("me.ele.ios.eleme")
		if err != nil {
			t.Fatal(err)
		}
		t.Log(container)

		apps, err := cli.InstalledApps()
		if err != nil {
			t.Fatal(err)
		}

		// t.Logf("%#v", apps)
		for k, v := range apps {
			t.Log(k, v)
		}
	}
}
