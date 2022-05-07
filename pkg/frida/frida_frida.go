//go:build frida
// +build frida

package frida

/*
 #include "frida-core.h"

 	void cgo_on_detached(FridaSession *session, FridaSessionDetachReason reason, FridaCrash *crash, gpointer user_data);
 	void cgo_on_message(FridaScript *script, const gchar *message, GBytes *data, gpointer user_data);
*/
import "C"
import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/buger/jsonparser"
	"golang.org/x/xerrors"
)

var writer io.Writer

func StartFrida(ctx context.Context, wr io.Writer, bundleId string) error {
	if strings.TrimSpace(bundleId) == "" {
		return xerrors.New("bundleId 不允许为空")
	}

	writer = wr

	if _, err := C.frida_init(); err != nil {
		return xerrors.Errorf("frida_init error: %w", err)
	}
	defer C.frida_deinit()

	loop := C.g_main_loop_new(nil, C.int(1))

	hDeviceManager := C.frida_device_manager_new()

	var gErr *C.GError
	hDeviceList := C.frida_device_manager_enumerate_devices_sync(hDeviceManager, nil, &gErr)
	if gErr != nil {
		return xerrors.Errorf("enumerate devices error: %s", C.GoString(gErr.message))
	}

	var hDevice *C.FridaDevice
	nDeviceList := int(C.frida_device_list_size(hDeviceList))
	for i := 0; i < nDeviceList; i++ {
		hDevice = C.frida_device_list_get(hDeviceList, C.int(i))
		deviceType := C.frida_device_get_dtype(hDevice)
		if deviceType != C.FRIDA_DEVICE_TYPE_USB {
			C.g_object_unref(C.gpointer(hDevice))
			hDevice = nil
			continue
		}
	}
	C.frida_unref(C.gpointer(hDeviceList))

	if hDevice == nil {
		return xerrors.New("frida device not found")
	}

	pid := C.frida_device_spawn_sync(hDevice, C.CString(bundleId), nil, nil, &gErr)
	if gErr != nil {
		return xerrors.Errorf("spawn target error: %s", C.GoString(gErr.message))
	}
	hSession := C.frida_device_attach_sync(hDevice, pid, C.FRIDA_REALM_NATIVE, nil, &gErr)
	if gErr != nil {
		return xerrors.Errorf("attach target error: %s", C.GoString(gErr.message))
	}

	C.g_signal_connect_data(C.gpointer(hSession), C.CString("detached"),
		C.GCallback(C.cgo_on_detached), nil, nil, 0)
	if int(C.frida_session_is_detached(hSession)) == 1 {
		panic("detached")
	}

	C.frida_device_resume_sync(hDevice, pid, nil, nil)

	fmt.Println("Attached")

	hScript := C.frida_session_create_script_sync(hSession, C.CString(fridaScript), nil, nil, &gErr)
	if gErr != nil {
		return xerrors.Errorf("create script error: %s", C.GoString(gErr.message))
	}

	C.g_signal_connect_data(C.gpointer(hScript), C.CString("message"),
		C.GCallback(C.cgo_on_message), nil, nil, 0)

	C.frida_script_load_sync(hScript, nil, &gErr)
	if gErr != nil {
		return xerrors.Errorf("load script error: %s", C.GoString(gErr.message))
	}

	fmt.Println("Script loaded")

	go func() {
		<-ctx.Done()
		C.g_main_loop_quit(loop)
	}()

	ok := C.g_main_loop_is_running(loop)
	if ok == 1 {
		C.g_main_loop_run(loop)
	}

	fmt.Println("Stopped")

	C.frida_script_unload_sync(hScript, nil, nil)
	C.frida_unref(C.gpointer(hScript))
	fmt.Println("Unloaded")

	C.frida_session_detach_sync(hSession, nil, nil)
	C.frida_unref(C.gpointer(hSession))
	fmt.Println("Detached")

	C.frida_unref(C.gpointer(hDevice))
	C.frida_device_manager_close_sync(hDeviceManager, nil, nil)
	C.frida_unref(C.gpointer(hDeviceManager))
	fmt.Println("Closed")

	C.g_main_loop_unref(loop)

	return nil
}

//export onDetached
// 设备被拔出
func onDetached(session *C.FridaSession, reason C.FridaSessionDetachReason, crash *C.FridaCrash, data C.gpointer) {

}

//export onMessage
func onMessage(script *C.FridaScript, message *C.gchar, data *C.GBytes, userData C.gpointer) {
	msg, err := jsonparser.GetString([]byte(C.GoString(message)), "payload")
	if err != nil {
		panic(err)
	}

	if writer != nil {
		_, _ = writer.Write([]byte(msg + "\n"))
	}
}
