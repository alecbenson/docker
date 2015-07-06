// +build linux

package server

// #include <stdlib.h>
// #include "/usr/include/pwd.h"
import "C"
import (
	"bytes"
	"fmt"
	"log/syslog"
	"net/http"
	"net/url"
	"path"
	"reflect"

	"github.com/docker/docker/daemon"
)

//Retrieves the container and "action" (start, stop, kill, etc) from the http request
func (s *Server) parseRequest(requrl string) (string, *daemon.Container) {
	parsedurl, err := url.Parse(requrl)
	if err != nil {
		return "?", nil
	}

	action := path.Base(parsedurl.Path)
	containerID := path.Base(path.Dir(parsedurl.Path))
	c, err := s.daemon.Get(containerID)
	if err != nil {
		return action, nil
	}
	return action, c
}

//Traverses the config struct and grabs non-standard values for logging
func parseConfig(config interface{}) string {
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

//Constructs a partial log message containing the container's configuration settings
func generateContainerConfigMsg(c *daemon.Container) string {
	if c != nil {
		config_stripped := parseConfig(*c.Config)
		hostConfig_stripped := parseConfig(*c.HostConfig())
		return fmt.Sprintf("ContainerID=%v, Config=%v HostConfig=%v", c.ID, config_stripped, hostConfig_stripped)
	}
	return ""
}

//Logs a docker API function after retrieving the user's credentials
func (s *Server) LogAction(w http.ResponseWriter, r *http.Request) error {
	user := getUserFromHttpResponseWriter(w)
	return s.LogAuthAction(w, r, user, false)
}

//Logs a docker API function and records the user that initiated the request using the authentication results
func (s *Server) LogAuthAction(w http.ResponseWriter, r *http.Request, user User, requireAuthn bool) error {
	//Success determines if the authorization was successful or not
	success := (user.HaveUid && user.Name != "") || !requireAuthn
	var message string
	action, c := s.parseRequest(r.RequestURI)

	switch action {
	case "create", "start":
		message += generateContainerConfigMsg(c)
		fallthrough
	default:
		if user.HaveUid {
			message = fmt.Sprintf("LoginUID=%v, ", user.Uid) + message
		}
		//Get username
		if user.Name != "" {
			message = fmt.Sprintf("Username=%v, ", user.Name) + message
		}
	}
	//This occurs when authentication is required and fails
	//If no authentication is being used by the daemon, "success" is always true
	if !success {
		message = fmt.Sprintf("{AuthSuccess=%v, Action=%v, %s}", success, action, message)
		logSyslog(message)
		return nil
	}
	message = fmt.Sprintf("{Action=%v, %s}", action, message)
	logSyslog(message)
	return nil
}

//Logs a message to the syslog
func logSyslog(message string) {
	logger, err := syslog.New(syslog.LOG_ALERT, "Docker")
	defer logger.Close()
	if err != nil {
		fmt.Printf("Error logging to syslog: %v", err)
	}
	logger.Info(message)
}
