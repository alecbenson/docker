// +build linux

package server

import "testing"

func TestParseRequest(t *testing.T) {
	testServ := &Server{}
	requrl1 := "/v1.20/containers/b998ae8c872c2c06c67f808df12eff2ffc58e294e3a320592abe2904b71dd12f/resize?h=55&w=104"
	requrl2 := "/v1.20/containers/b998ae8c872c2c06c67f808df12eff2ffc58e294e3a320592abe2904b71dd12f/attach?stderr=1&stdin=1&stdout=1&stream=1"
	requrl3 := "/v1.20/containers/create"
	requrl4 := "/v1.20/containers/254c95dc36fff12f736f7cb8b130edf6175df020e55e65b4df90012e3922a12e/start"

	if action, _ := testServ.parseRequest(requrl1); action != "resize" {
		t.Fatal("Expected parse request to return action 'resize'. Got %v instead", action)
	}
	if action, _ := testServ.parseRequest(requrl1); action != "attach" {
		t.Fatal("Expected parse request to return action 'attach'. Got %v instead", action)
	}
	if action, _ := testServ.parseRequest(requrl1); action != "create" {
		t.Fatal("Expected parse request to return action 'create'. Got %v instead", action)
	}
	if action, _ := testServ.parseRequest(requrl1); action != "start" {
		t.Fatal("Expected parse request to return action 'start'. Got %v instead", action)
	}
}
