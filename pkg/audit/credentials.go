// +build linux

package audit

import (
	"fmt"
	"github.com/Sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"reflect"
	"strconv"
	"syscall"
)

func ReadUcred(w http.ResponseWriter, r *http.Request) (*syscall.Ucred, error) {
	//We must use introspection to pull the
	//connection from the ResponseWriter object
	wv := reflect.ValueOf(w)

	switch we := wv.Elem(); we.Kind() {
	case reflect.Struct:
		cv := we.FieldByName("conn")
		ce := cv.Elem()
		rwcv := ce.FieldByName("rwc")
		rwce := rwcv.Elem()
		rwce = rwce.Elem()
		cv = rwce.FieldByName("conn")

		switch cv.Kind() {
		case reflect.Struct:
			fdv := cv.FieldByName("fd")
			fde := fdv.Elem()

			switch fde.Kind() {
			case reflect.Struct:
				fd := fde.FieldByName("sysfd")
				return syscall.GetsockoptUcred(int(fd.Int()), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
			}
		}
	}
	return nil, nil
}

//Generates a  AuditUcred struct containing the login UID and ucred struct of the socket connection
func ReadLoginUid(ucred *syscall.Ucred) (int, error) {
	loginuid, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/loginuid", ucred.Pid))
	if err != nil {
		logrus.Errorf("Error reading loginuid: %v", err)
		return -1, err
	}

	loginuid_int, err := strconv.Atoi(string(loginuid))
	if err != nil {
		logrus.Errorf("Failed to convert loginuid to int: %v", err)
	}
	return loginuid_int, nil
}
