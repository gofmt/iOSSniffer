//go:build frida
// +build frida

package frida

/*
 #cgo CFLAGS: -g -O2 -w -I. -I./
 #cgo LDFLAGS: -framework Foundation -framework AppKit -lbsm -lresolv -L./ -lfrida-core
 // #cgo LDFLAGS: -static-libgcc -L${SRCDIR}/libs -lfrida-core -ldl -lm -lrt -lresolv -lpthread -Wl,--export-dynamic
 #include "frida-core.h"

 void cgo_on_detached(FridaSession *session, FridaSessionDetachReason reason, FridaCrash *crash, gpointer user_data) {
	onDetached(session, reason, crash, user_data);
 }
 void cgo_on_message(FridaScript *script, const gchar *message, GBytes *data, gpointer user_data) {
	onMessage(script, message, data, user_data);
 }
*/
import "C"

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
