package execdriver

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	// TODO Windows: Factor out ulimit
	"github.com/docker/libcontainer/configs"
)

type Mount struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Writable    bool   `json:"writable"`
	Private     bool   `json:"private"`
	Slave       bool   `json:"slave"`
}

func (m *Mount) Config(c *Command) *configs.Mount {
	if m.Source == "tmpfs" {
		dest := filepath.Join(c.Rootfs, m.Destination)
		flags := syscall.MS_NOSUID | syscall.MS_NODEV
		return &configs.Mount{
			Source:        m.Source,
			Destination:   m.Destination,
			Device:        "tmpfs",
			Data:          "mode=755,size=65536k",
			Flags:         flags,
			PremountCmds:  genPremountCmd(c.TmpDir, dest, m.Destination),
			PostmountCmds: genPostmountCmd(c.TmpDir, dest, m.Destination),
		}
	}

	flags := syscall.MS_BIND | syscall.MS_REC
	if !m.Writable {
		flags |= syscall.MS_RDONLY
	}
	if m.Slave {
		flags |= syscall.MS_SLAVE
	}
	return &configs.Mount{
		Source:      m.Source,
		Destination: m.Destination,
		Device:      "bind",
		Flags:       flags,
	}
}
func genPremountCmd(tmpDir string, fullDest string, dest string) []configs.Command {
	var premount []configs.Command
	tarFile := fmt.Sprintf("%s/%s.tar", tmpDir, strings.Replace(dest, "/", "_", -1))
	if _, err := os.Stat(fullDest); err == nil {
		premount = append(premount, configs.Command{
			Path: "/usr/bin/tar",
			Args: []string{"-cf", tarFile, "-C", fullDest, "."},
		})
	}
	return premount
}

func genPostmountCmd(tmpDir string, fullDest string, dest string) []configs.Command {
	var postmount []configs.Command
	if _, err := os.Stat(fullDest); os.IsNotExist(err) {
		return postmount
	}
	tarFile := fmt.Sprintf("%s/%s.tar", tmpDir, strings.Replace(dest, "/", "_", -1))
	postmount = append(postmount, configs.Command{
		Path: "/usr/bin/tar",
		Args: []string{"-xf", tarFile, "-C", fullDest, "."},
	})
	return append(postmount, configs.Command{
		Path: "/usr/bin/rm",
		Args: []string{"-f", tarFile},
	})
}
