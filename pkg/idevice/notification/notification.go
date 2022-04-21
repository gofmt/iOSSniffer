package notification

import (
	"github.com/gofmt/iOSSniffer/pkg/idevice"
	"github.com/gofmt/iOSSniffer/pkg/idevice/lockdownd"
)

const (
	serviceName = "com.apple.mobile.notification_proxy"
)

type RequestBase struct {
	Command string `plist:"Command"`
}

type ObserveNotificationRequest struct {
	RequestBase
	Name string `plist:"Name"`
}

type ObserveNotificationEvent struct {
	RequestBase
	Name string `plist:"Name"`
}

type Client struct {
	c *idevice.Client
}

func NewClient(udid string) (*Client, error) {
	c, err := lockdownd.NewClientForService(serviceName, udid, false)
	if err != nil {
		return nil, err
	}
	return &Client{
		c: c,
	}, nil
}

func (c *Client) ObserveNotification(notification string) error {
	req := ObserveNotificationRequest{
		RequestBase: RequestBase{"ObserveNotification"},
		Name:        notification,
	}
	_ = req
	return nil
}

func (c *Client) Close() error {
	return c.c.Close()
}
