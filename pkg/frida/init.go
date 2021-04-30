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
