// +build linux,cgo,!static_build,gssapi

package client

import (
	"encoding/base64"
	"net/http"
	"strings"
	"unsafe"

	"github.com/Sirupsen/logrus"
)

// #cgo pkg-config: krb5-gssapi
// #include <sys/types.h>
// #include <stdlib.h>
// #include <gssapi/gssapi.h>
//
// gss_OID_desc SpnegoOid = {
// 	.length = 6,
// 	.elements = "\053\006\001\005\005\002"
// };
import "C"

type negotiate struct {
}

func getErrorDesc(major, minor C.OM_uint32, mech C.gss_OID) string {
	var mj, mn C.gss_buffer_desc
	var str string
	var cm, mc C.OM_uint32

	major = C.gss_display_status(&cm, major, C.GSS_C_GSS_CODE, nil, &mc, &mj)
	if major == 0 && mj.value != nil && mj.length > 0 {
		str = string(C.GoBytes(mj.value, C.int(mj.length)))
		C.gss_release_buffer(nil, &mj)
	}
	if minor != 0 {
		major = C.gss_display_status(&cm, minor, C.GSS_C_MECH_CODE, mech, &mc, &mn)
		if major == 0 && mn.value != nil && mn.length > 0 {
			if str != "" {
				str = str + ": " + string(C.GoBytes(mn.value, C.int(mn.length)))
			} else {
				str = "?: " + string(C.GoBytes(mn.value, C.int(mn.length)))
			}
			C.gss_release_buffer(nil, &mn)
		}
	}
	return str
}

func (n negotiate) Scheme() string {
	return "Negotiate"
}

func (n negotiate) AuthRespond(cli *DockerCli, challenge string, req *http.Request) (result bool, err error) {
	var itoken, otoken, namebuf C.gss_buffer_desc
	var itokenptr *C.gss_buffer_desc
	var ctx C.gss_ctx_id_t
	var minor, lifetime, flags C.OM_uint32
	var name C.gss_name_t
	var mech C.gss_OID

	fields := strings.SplitN(strings.Replace(challenge, "\t", " ", -1), " ", 2)
	if fields[0] == "Negotiate" {
		if len(fields) > 1 {
			token, err := base64.StdEncoding.DecodeString(fields[1])
			if err != nil {
				logrus.Errorf("error decoding Negotiate token from server: \"%s\"", fields[1])
				return false, err
			}
			itoken.value = unsafe.Pointer(&token[0])
			itoken.length = C.size_t(len(token))
			itokenptr = &itoken
		}
		serverhost := req.Host
		if serverhost == "" {
			serverhost = req.URL.Host
		}
		sep := strings.LastIndex(serverhost, ":")
		if sep > -1 && sep > strings.LastIndex(serverhost, "]") {
			serverhost = serverhost[:sep]
		}
		serverhost = "HTTP@" + serverhost
		logrus.Debugf("gssapi: using service name \"%s\"", serverhost)
		namebuf.value = unsafe.Pointer(C.CString(serverhost))
		defer C.free(namebuf.value)
		namebuf.length = C.size_t(len(serverhost))
		mech = &C.SpnegoOid
		major := C.gss_import_name(&minor, &namebuf, C.GSS_C_NT_HOSTBASED_SERVICE, &name)
		if name != nil {
			defer C.gss_release_name(&minor, &name)
		}
		if major != 0 {
			logrus.Infof("error importing server name (%s), not attempting Negotiate auth", getErrorDesc(major, minor, nil))
			return false, nil
		}
		lifetime = C.GSS_C_INDEFINITE
		major = C.gss_init_sec_context(&minor, nil, &ctx, name, mech, flags, lifetime, nil, itokenptr, nil, &otoken, nil, nil)
		if ctx != nil {
			defer C.gss_delete_sec_context(&minor, &ctx, nil)
		}
		if otoken.length > 0 {
			defer C.gss_release_buffer(&minor, &otoken)
		}
		if major != 0 && major != C.GSS_S_CONTINUE_NEEDED {
			logrus.Infof("error generating GSSAPI session initiation token (%s), not attempting Negotiate auth", getErrorDesc(major, minor, nil))
			return false, nil
		} else {
			if otoken.length > 0 {
				response := C.GoBytes(otoken.value, C.int(otoken.length))
				token := base64.StdEncoding.EncodeToString(response)
				req.Header.Add("Authorization", "Negotiate "+token)
				logrus.Debugf("gssapi: generated token \"%s\"", token)
				if major == C.GSS_S_CONTINUE_NEEDED {
					logrus.Warningf("gssapi: continue needed")
				}
				return true, nil
			}
		}
	}
	return false, nil
}

func createNegotiate() AuthResponder {
	return &negotiate{}
}

func init() {
	RegisterAuthResponder(createNegotiate)
}
