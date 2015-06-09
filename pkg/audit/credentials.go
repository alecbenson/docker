package audit

import (
	"fmt"
	"github.com/Sirupsen/logrus"
	"github.com/docker/docker/daemon"
	"github.com/docker/libcontainer/user"
	"io/ioutil"
	"net/http"
	"reflect"
	"runtime"
	"strconv"
	"syscall"
)

func readUcred(w http.ResponseWriter, r *http.Request) (*syscall.Ucred, error) {
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
func readLoginUid(ucred *syscall.Ucred) (int, error) {
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

//Called in server.go to log events to the audit log
func AuditLogEvent(action string, c *daemon.Container, w http.ResponseWriter, r *http.Request) error {
	if runtime.GOOS == "windows" {
		return nil
	}

	var message string
	image := c.Config.Image
	cmd := c.Config.Cmd
	name := c.Config.Hostname

	//Get user name
	username, err := user.CurrentUser()
	if err != nil {
		logrus.Errorf("Error reading username: %v\n", err)

		message = fmt.Sprintf("type=docker action=%s cmd=%s image=%s name=%s",
			action, cmd, image, name)
		return AuditLogUserEvent(AUDIT_VIRT_CONTROL, message, true)
	}

	//Get user credentials
	ucred, err := readUcred(w, r)
	if err != nil {
		logrus.Errorf("Error reading ucred: %v\n", err)
		message = fmt.Sprintf("type=docker action=%s uname=%s cmd=%s image=%s name=%s",
			action, username.Name, cmd, image, name)
		return AuditLogUserEvent(AUDIT_VIRT_CONTROL, message, true)
	}

	//Get user loginuid
	loginuid, err := readLoginUid(ucred)
	if err != nil {
		logrus.Errorf("Error reading loginuid: %v\n", err)
		message = fmt.Sprintf("type=docker action=%s uname=%s cmd=%s image=%s name=%s",
			action, cmd, image, name)
		return AuditLogUserEvent(AUDIT_VIRT_CONTROL, message, true)
	}

	message = fmt.Sprintf("type=docker action=%s uname=%s auid=%d cmd=%s image=%s name=%s",
		action, username.Name, loginuid, cmd, image, name)
	return AuditLogUserEvent(AUDIT_VIRT_CONTROL, message, true)
}
