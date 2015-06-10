// +build linux

package audit

import (
	"bytes"
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

//Traverses the config struct and grabs non-standard values for logging
func ParseConfig(config interface{}) string {
	configReflect := reflect.ValueOf(config)
	var result bytes.Buffer

	for index := 0; index < configReflect.NumField(); index++ {
		val := reflect.Indirect(configReflect.Field(index))

		//Get the zero value of the struct's field
		if val.IsValid() {
			zeroVal := reflect.Zero(val.Type()).Interface()

			//If the configuration value is not a zero value, then we store it
			//We use deep equal here because some types cannot be compared with the standard equality operators
			if val.Kind() == reflect.Bool || !reflect.DeepEqual(zeroVal, val.Interface()) {
				fieldName := configReflect.Type().Field(index).Name
				line := fmt.Sprintf("%s=%+v, ", fieldName, val.Interface())
				result.WriteString(line)

			}
		}
	}
	return result.String()
}
