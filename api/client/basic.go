package client

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/docker/docker/pkg/term"
)

type basic struct {
}

func (b *basic) Scheme() string {
	return "Basic"
}

func (b *basic) AuthRespond(cli *DockerCli, challenge string, req *http.Request) (result bool, err error) {
	var user, pass string

	readInput := func(in io.Reader, out io.Writer) string {
		reader := bufio.NewReader(in)
		line, _, err := reader.ReadLine()
		if err != nil {
			fmt.Fprintln(out, err.Error())
			os.Exit(1)
		}
		return string(line)
	}

	for user == "" {
		fmt.Fprintf(cli.out, "Username: ")
		user = readInput(cli.in, cli.out)
		user = strings.Trim(user, " ")
	}

	oldState, err := term.SaveState(cli.inFd)
	if err != nil {
		return false, err
	}
	fmt.Fprintf(cli.out, "Password: ")
	term.DisableEcho(cli.inFd, oldState)

	pass = readInput(cli.in, cli.out)
	fmt.Fprint(cli.out, "\n")

	term.RestoreTerminal(cli.inFd, oldState)
	if pass == "" {
		return false, fmt.Errorf("Error: Password Required")
	}

	req.SetBasicAuth(user, pass)
	return true, nil
}

func createBasic() AuthResponder {
	return &basic{}
}

func init() {
	RegisterAuthResponder(createBasic)
}
