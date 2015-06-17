// +build linux,cgo,!static_build,daemon,gssapi

package server

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
// #include <gssapi/gssapi_krb5.h>
import "C"

type negotiator struct {
	Scheme string
	Name   string
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

func (n *negotiator) GetChallenge(w http.ResponseWriter, r *http.Request) error {
	w.Header().Add("WWW-Authenticate", "Negotiate")
	return nil
}

func (n *negotiator) CheckResponse(w http.ResponseWriter, r *http.Request) (User, error) {
	var ctx C.gss_ctx_id_t
	var creds C.gss_cred_id_t
	var itoken, otoken, namebuf C.gss_buffer_desc
	var minor, lifetime, flags C.OM_uint32
	var name C.gss_name_t
	var mech C.gss_OID
	var client string
	var reply []byte

	ah := r.Header["Authorization"]
	for _, h := range ah {
		fields := strings.SplitN(strings.Replace(h, "\t", " ", -1), " ", 2)
		if fields[0] == "Negotiate" {
			logrus.Debugf("gssapi: got token \"%s\"", fields[1])
			token, err := base64.StdEncoding.DecodeString(fields[1])
			if err != nil {
				logrus.Errorf("error decoding Negotiate token: \"%s\"", fields[1])
				return User{}, err
			}
			major := C.gss_acquire_cred(&minor, nil, C.GSS_C_INDEFINITE, nil, C.GSS_C_ACCEPT, &creds, nil, nil)
			if major != 0 {
				logrus.Infof("error acquiring GSSAPI acceptor creds (%s), not accepting Negotiate auth", getErrorDesc(major, minor, nil))
				return User{}, nil
			} else {
				defer C.gss_release_cred(nil, &creds)
			}
			itoken.value = unsafe.Pointer(&token[0])
			itoken.length = C.size_t(len(token))
			major = C.gss_accept_sec_context(&minor, &ctx, creds, &itoken, nil, &name, &mech, &otoken, &flags, &lifetime, nil)
			if otoken.length > 0 {
				reply = C.GoBytes(otoken.value, C.int(otoken.length))
				C.gss_release_buffer(&minor, &otoken)
			}
			if major != 0 {
				logrus.Errorf("error accepting GSSAPI context (%s) in a single pass, failed Negotiate auth", getErrorDesc(major, minor, mech))
				return User{}, nil
			} else {
				defer C.gss_delete_sec_context(&minor, &ctx, nil)
			}
			major = C.gss_localname(&minor, name, mech, &namebuf)
			if major != 0 {
				logrus.Errorf("error converting GSSAPI client name to local name (%s), failed Negotiate auth", getErrorDesc(major, minor, mech))
				return User{}, nil
			} else {
				client = string(C.GoBytes(namebuf.value, C.int(namebuf.length)))
				C.gss_release_buffer(&minor, &namebuf)
			}
			if len(reply) > 0 {
				token := base64.StdEncoding.EncodeToString(reply)
				logrus.Debugf("gssapi: produced reply token \"%s\"", token)
				w.Header().Add("WWW-Authenticate", "Negotiate "+token)
			}
			return User{Name: client}, nil
		}
	}
	return User{}, nil
}

func createNegotiate(options ServerAuthOptions) Authenticator {
	var creds C.gss_cred_id_t
	var minor C.OM_uint32

	if options.Keytab != "" {
		keytab := C.CString(options.Keytab)
		defer C.free(unsafe.Pointer(keytab))
		major := C.gsskrb5_register_acceptor_identity(keytab)
		if major != 0 {
			logrus.Errorf("error registering keytab \"%s\": %s", options.Keytab, getErrorDesc(major, 0, nil))
			return nil
		}
	}
	major := C.gss_acquire_cred(&minor, nil, C.GSS_C_INDEFINITE, nil, C.GSS_C_ACCEPT, &creds, nil, nil)
	if major != 0 {
		logrus.Debugf("unable to acquire GSSAPI acceptor creds (%s), not offering Negotiate auth", getErrorDesc(major, minor, nil))
		return nil
	} else {
		defer C.gss_release_cred(nil, &creds)
	}
	return &negotiator{Scheme: "Negotiate", Name: "gssapi"}
}

func init() {
	RegisterAuthenticator(createNegotiate)
}
