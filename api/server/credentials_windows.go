// +build windows

package server

import (
	"net/http"
)

//Audit/system logging is unsupported in windows environments
func (s *Server) LogAuthAction(w http.ResponseWriter, r *http.Request, user User, requireAuthn bool) error {
	return nil
}

//Audit/system logging is unsupported in windows environments
func (s *Server) LogAction(w http.ResponseWriter, r *http.Request) error {
	return nil
}
