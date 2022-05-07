//go:build !frida
// +build !frida

package frida

import (
	"context"
	"io"
)

func StartFrida(ctx context.Context, wr io.Writer, bundleId string) error {
	return nil
}
