package daemon

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/docker/docker/daemon/execdriver"
	"github.com/docker/docker/pkg/archive"
	"github.com/docker/docker/pkg/log"
	"github.com/docker/docker/pkg/symlink"
	"github.com/docker/docker/volumes"
	"github.com/docker/libcontainer/label"
)

type Mount struct {
	MountToPath string
	container   *Container
	volume      *volumes.Volume
	Mode        string
	copyData    bool
}

func (container *Container) prepareVolumes() error {
	if container.Volumes == nil || len(container.Volumes) == 0 {
		container.Volumes = make(map[string]string)
		container.VolumesMode = make(map[string]string)
		if err := container.applyVolumesFrom(); err != nil {
			return err
		}
	}

	return container.createVolumes()
}

// sortedVolumeMounts returns the list of container volume mount points sorted in lexicographic order
func (container *Container) sortedVolumeMounts() []string {
	var mountPaths []string
	for path := range container.Volumes {
		mountPaths = append(mountPaths, path)
	}

	sort.Strings(mountPaths)
	return mountPaths
}

func (container *Container) createVolumes() error {
	mounts, err := container.parseVolumeMountConfig()
	if err != nil {
		return err
	}

	for _, mnt := range mounts {
		if err := mnt.initialize(); err != nil {
			return err
		}
	}

	return nil
}

func (m *Mount) initialize() error {
	// No need to initialize anything since it's already been initialized
	if _, exists := m.container.Volumes[m.MountToPath]; exists {
		return nil
	}

	// This is the full path to container fs + mntToPath
	containerMntPath, err := symlink.FollowSymlinkInScope(filepath.Join(m.container.basefs, m.MountToPath), m.container.basefs)
	if err != nil {
		return err
	}
	m.container.VolumesMode[m.MountToPath] = m.Mode
	m.container.Volumes[m.MountToPath] = m.volume.Path
	m.volume.AddContainer(m.container.ID)
	if volumes.Writable(m.Mode) && m.copyData {
		// Copy whatever is in the container at the mntToPath to the volume
		copyExistingContents(containerMntPath, m.volume.Path)
	}

	return nil
}

func (container *Container) VolumePaths() map[string]struct{} {
	var paths = make(map[string]struct{})
	for _, path := range container.Volumes {
		paths[path] = struct{}{}
	}
	return paths
}

func (container *Container) registerVolumes() {
	for _, mnt := range container.VolumeMounts() {
		mnt.volume.AddContainer(container.ID)
	}
}

func (container *Container) derefVolumes() {
	for path := range container.VolumePaths() {
		vol := container.daemon.volumes.Get(path)
		if vol == nil {
			log.Debugf("Volume %s was not found and could not be dereferenced", path)
			continue
		}
		vol.RemoveContainer(container.ID)
	}
}

func (container *Container) parseVolumeMountConfig() (map[string]*Mount, error) {
	var mounts = make(map[string]*Mount)
	// Get all the bind mounts
	for _, spec := range container.hostConfig.Binds {
		path, mountToPath, mode, err := parseBindMountSpec(spec)
		if err != nil {
			return nil, err
		}
		// Check if a volume already exists for this and use it
		vol, err := container.daemon.volumes.FindOrCreateVolume(path, mode)
		if err != nil {
			return nil, err
		}
		mounts[mountToPath] = &Mount{
			container:   container,
			volume:      vol,
			MountToPath: mountToPath,
			Mode:        mode,
		}
	}

	// Get the rest of the volumes
	for path := range container.Config.Volumes {
		// Check if this is already added as a bind-mount
		if _, exists := mounts[path]; exists {
			continue
		}

		// Check if this has already been created
		if _, exists := container.Volumes[path]; exists {
			continue
		}

		vol, err := container.daemon.volumes.FindOrCreateVolume("", "w")
		if err != nil {
			return nil, err
		}
		mounts[path] = &Mount{
			container:   container,
			MountToPath: path,
			volume:      vol,
			Mode:        "w",
			copyData:    true,
		}
	}

	return mounts, nil
}

func parseBindMountSpec(spec string) (string, string, string, error) {
	var (
		path, mountToPath string
		mode              string
		arr               = strings.Split(spec, ":")
	)

	switch len(arr) {
	case 2:
		path = arr[0]
		mountToPath = arr[1]
	case 3:
		if !volumes.ValidMode(arr[2]) {
			return "", "", "", fmt.Errorf("Invalid volume options specification: %s", spec)
		}
		path = arr[0]
		mountToPath = arr[1]
		mode = arr[2]
	default:
		return "", "", "", fmt.Errorf("Invalid volume specification: %s", spec)
	}

	if !filepath.IsAbs(path) {
		return "", "", "", fmt.Errorf("cannot bind mount volume: %s volume paths must be absolute.", path)
	}

	return path, mountToPath, mode, nil
}

func (container *Container) applyVolumesFrom() error {
	volumesFrom := container.hostConfig.VolumesFrom

	for _, spec := range volumesFrom {
		mounts, err := parseVolumesFromSpec(container.daemon, spec)
		if err != nil {
			return err
		}

		for _, mnt := range mounts {
			mnt.container = container
			if err = mnt.initialize(); err != nil {
				return err
			}
		}
	}
	return nil
}

func (container *Container) setupMounts() error {
	mounts := []execdriver.Mount{
		{Source: container.ResolvConfPath, Destination: "/etc/resolv.conf", Mode: "w", Private: true},
	}
	if container.HostnamePath != "" {
		mounts = append(mounts, execdriver.Mount{Source: container.HostnamePath, Destination: "/etc/hostname", Mode: "w", Private: true})
	}

	if container.HostsPath != "" {
		mounts = append(mounts, execdriver.Mount{Source: container.HostsPath, Destination: "/etc/hosts", Mode: "w", Private: true})
	}

	if container.hostConfig.MountRun {
		runMount, err := setupRun(container)
		if err != nil {
			return err
		}
		mounts = append(mounts, *runMount)
	}

	// Mount user specified volumes
	// Note, these are not private because you may want propagation of (un)mounts from host
	// volumes. For instance if you use -v /usr:/usr and the host later mounts /usr/share you
	// want this new mount in the container
	// These mounts must be ordered based on the length of the path that it is being mounted to (lexicographic)
	for _, path := range container.sortedVolumeMounts() {
		mounts = append(mounts, execdriver.Mount{
			Source:      container.Volumes[path],
			Destination: path,
			Mode:        container.VolumesMode[path],
		})
	}

	secretsPath, err := container.secretsPath()
	if err != nil {
		return err
	}

	mounts = append(mounts, execdriver.Mount{
		Source:      secretsPath,
		Destination: "/run/secrets",
		Mode:        "w",
	})

	container.command.Mounts = mounts
	return nil
}

func parseVolumesFromSpec(daemon *Daemon, spec string) (map[string]*Mount, error) {
	specParts := strings.SplitN(spec, ":", 2)
	if len(specParts) == 0 {
		return nil, fmt.Errorf("Malformed volumes-from specification: %s", spec)
	}

	c := daemon.Get(specParts[0])
	if c == nil {
		return nil, fmt.Errorf("Container %s not found. Impossible to mount its volumes", specParts[0])
	}

	mounts := c.VolumeMounts()

	if len(specParts) == 2 {
		mode := specParts[1]
		if !volumes.ValidMode(mode) {
			return nil, fmt.Errorf("Invalid mode for volumes-from: %s", mode)
		}

		// Set the mode for the inheritted volume
		for _, mnt := range mounts {
			// Ensure that if the inherited volume is not writable, that we don't make
			// it writable here
			if volumes.Writable(mode) && !volumes.Writable(mnt.Mode) {
				mnt.Mode = volumes.MakeReadOnly(mnt.Mode)
			}
		}
	}

	return mounts, nil
}

func (container *Container) VolumeMounts() map[string]*Mount {
	mounts := make(map[string]*Mount)

	for mountToPath, path := range container.Volumes {
		if v := container.daemon.volumes.Get(path); v != nil {
			mounts[mountToPath] = &Mount{volume: v, container: container, MountToPath: mountToPath, Mode: container.VolumesMode[mountToPath]}
		}
	}

	return mounts
}

func copyExistingContents(source, destination string) error {
	volList, err := ioutil.ReadDir(source)
	if err != nil {
		return err
	}

	if len(volList) > 0 {
		srcList, err := ioutil.ReadDir(destination)
		if err != nil {
			return err
		}

		if len(srcList) == 0 {
			// If the source volume is empty copy files from the root into the volume
			if err := archive.CopyWithTar(source, destination); err != nil {
				return err
			}
		}
	}

	return copyOwnership(source, destination)
}

// copyOwnership copies the permissions and uid:gid of the source file
// into the destination file
func copyOwnership(source, destination string) error {
	var stat syscall.Stat_t

	if err := syscall.Stat(source, &stat); err != nil {
		return err
	}

	if err := os.Chown(destination, int(stat.Uid), int(stat.Gid)); err != nil {
		return err
	}

	return os.Chmod(destination, os.FileMode(stat.Mode))
}

func setupRun(container *Container) (*execdriver.Mount, error) {
	runPath, err := container.runPath()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(runPath, 0700); err != nil && !os.IsExist(err) {
		return nil, err
	}

	if err := syscall.Mount("tmpfs", runPath, "tmpfs", uintptr(syscall.MS_NOEXEC|syscall.MS_NOSUID|syscall.MS_NODEV), label.FormatMountLabel("", container.GetMountLabel())); err != nil {
		return nil, fmt.Errorf("mounting run tmpfs: %s", err)
	}

	runSource, err := symlink.FollowSymlinkInScope(filepath.Join(container.basefs, "/run"), container.basefs)
	if err != nil {
		return nil, err
	}

	if err := archive.CopyWithTar(runSource, runPath); err != nil {
		return nil, err
	}

	return &execdriver.Mount{
		Source:      runPath,
		Destination: "/run",
		Mode:        "w",
		Private:     true}, nil
}
