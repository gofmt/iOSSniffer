package frida

import (
	"context"
	"os"
	"testing"
	"time"
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

func TestFrida(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	f, err := os.OpenFile("test.keylog", os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = f.Close()
	}()

	if err := StartFrida(ctx, f, "com.elong.app", fridaScript); err != nil {
		panic(err)
	}
}
