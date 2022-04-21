package lockdownd

import (
	"github.com/gofmt/iOSSniffer/pkg/idevice"
)

type Client struct {
	*idevice.Client
}

type startSessionRequest struct {
	Label           string
	ProtocolVersion string
	Request         string
	HostID          string
	SystemBUID      string
}

type startSessionResponse struct {
	Request          string
	Result           string
	EnableSessionSSL bool
	SessionID        string
}

func NewClient(udid string) (*Client, error) {
	cli, err := idevice.NewClient(udid, 62078)
	if err != nil {
		return nil, err
	}
	req := &startSessionRequest{
		Label:           idevice.BundleID,
		ProtocolVersion: "2",
		Request:         "StartSession",
		HostID:          cli.PairRecord().HostID,
		SystemBUID:      cli.PairRecord().SystemBUID,
	}
	var resp startSessionResponse
	if err := cli.Request(req, &resp); err != nil {
		return nil, err
	}

	if resp.EnableSessionSSL {
		if err := cli.EnableSSL(); err != nil {
			return nil, err
		}
	}

	return &Client{cli}, nil
}

func NewClientForService(serviceName, udid string, withEscrowBag bool) (*idevice.Client, error) {
	lc, err := NewClient(udid)
	if err != nil {
		return nil, err
	}
	defer func(lc *Client) {
		_ = lc.Close()
	}(lc)

	svc, err := lc.StartService(serviceName, withEscrowBag)
	if err != nil {
		return nil, err
	}

	cli, err := idevice.NewClient(udid, svc.Port)
	if err != nil {
		return nil, err
	}
	if svc.EnableServiceSSL {
		_ = cli.EnableSSL()
	}

	return cli, nil
}

type startServiceRequest struct {
	Request   string `plist:"Request"`
	Service   string
	EscrowBag []byte `plist:",omitempty"`
}

type StartServiceResponse struct {
	Request          string
	Result           string
	Service          string
	Port             int
	EnableServiceSSL bool
}

func (lc *Client) StartService(service string, withEscrowBag bool) (*StartServiceResponse, error) {
	req := &startServiceRequest{
		Request: "StartService",
		Service: service,
	}
	if withEscrowBag {
		req.EscrowBag = lc.PairRecord().EscrowBag
	}

	var resp StartServiceResponse
	if err := lc.Request(req, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

type DeviceValues struct {
	BasebandCertId             int
	BasebandKeyHashInformation struct {
		AKeyStatus int
		SKeyStatus int
	}
	BasebandSerialNumber    []byte
	BasebandVersion         string
	BoardId                 int
	BuildVersion            string
	CPUArchitecture         string
	ChipID                  int
	DeviceClass             string
	DeviceColor             string
	DeviceName              string
	DieID                   int
	HardwareModel           string
	HasSiDP                 bool
	PartitionType           string
	ProductName             string
	ProductType             string
	ProductVersion          string
	ProductionSOC           bool
	ProtocolVersion         string
	SupportedDeviceFamilies []int
	TelephonyCapability     bool
	UniqueChipID            int64
	UniqueDeviceID          string
	WiFiAddress             string
}

type getValueRequest struct {
	Label   string
	Request string
	Domain  string `plist:"Domain,omitempty"`
	Key     string `plist:"Key,omitempty"`
}

type getValueResponse struct {
	Request string
	Result  string
	Value   *DeviceValues
}

func (lc *Client) GetValues() (*DeviceValues, error) {
	req := &getValueRequest{
		Label:   idevice.BundleID,
		Request: "GetValue",
		Domain:  "",
		Key:     "",
	}
	var resp getValueResponse
	if err := lc.Request(req, &resp); err != nil {
		return nil, err
	}

	return resp.Value, nil
}

type queryTypeRequest struct {
	Request string `plist:"Request"`
}

type queryTypeResponse struct {
	Request string
	Result  string
	Type    string
}

func (lc *Client) QueryType() (string, error) {
	req := &queryTypeRequest{
		Request: "QueryType",
	}
	var resp queryTypeResponse
	if err := lc.Request(req, &resp); err != nil {
		return "", err
	}

	return resp.Type, nil
}

func (lc *Client) Close() error {
	return lc.Client.Close()
}
