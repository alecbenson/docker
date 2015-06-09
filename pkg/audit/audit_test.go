package audit

import (
	"io/ioutil"
	"net"
	"testing"
)

func TestLibAudit(t *testing.T) {
	if audit.AuditValueNeedsEncoding("test") {
		t.Fatal("Expected false for AuditValueNeedsEncoding , received true: ")
	}
	if !audit.AuditValueNeedsEncoding("test test") {
		t.Fatal("Expected true for AuditValueNeedsEncoding , received false: ")
		return
	}
}

func GetUcred(t *testing.T) {
	lock := make(chan struct{})
	buffer, err := NewListenBuffer("tcp", "", lock)
	if err != nil {
		t.Fatal("Unable to create listen buffer: ", err)
	}

	go func() {
		conn, err := net.Dial("tcp", buffer.Addr().String())
		if err != nil {
			t.Fatal("Client failed to establish connection to server: ", err)
		}
		ucreds, err := audit.GetAuditUcred(conn)

		if !ucreds.Success {
			t.Fatal("Could not successfully get user credentials")
		}

		conn.Close()
	}()
	close(lock)

	client, err := buffer.Accept()
	if err != nil {
		t.Fatal("Failed to accept client: ", err)
	}+

}
