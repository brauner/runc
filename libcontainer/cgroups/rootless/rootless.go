// +build linux

package rootless

import (
	"fmt"

	"github.com/opencontainers/runc/libcontainer/cgroups"
	"github.com/opencontainers/runc/libcontainer/cgroups/fs"
	"github.com/opencontainers/runc/libcontainer/configs"
)

// The noop cgroup manager is used for rootless containers, because we currently
// cannot manage cgroups if we are in a rootless setup. This manager is chosen
// by factory if we are in rootless mode. We error out if any cgroup options are
// set in the config -- this may change in the future with upcoming kernel features
// like the cgroup namespace.

type Manager struct {
	Cgroups *configs.Cgroup
	Paths   map[string]string
}

func (m *Manager) Apply(pid int) error {
	// If there are no cgroup settings, there's nothing to do.
	if m.Cgroups == nil {
		return nil
	}

	// We can't set paths.
	// TODO(cyphar): Implement the case where the runner of a rootless container
	//               owns their own cgroup, which would allow us to set up a
	//               cgroup for each path.
	if m.Cgroups.Paths != nil {
		return fmt.Errorf("cannot change cgroup path in rootless container")
	}

	return nil
}

func (m *Manager) GetPaths() map[string]string {
	return m.Paths
}

func (m *Manager) Set(container *configs.Config) error {
	// We don't have to do any checks here. They were already done in validate/rootless.go.
	return nil
}

func (m *Manager) GetPids() ([]int, error) {
	dir, err := fs.GetCgroupPath(m.Cgroups)
	if err != nil {
		return nil, err
	}
	return cgroups.GetPids(dir)
}

func (m *Manager) GetAllPids() ([]int, error) {
	dir, err := fs.GetCgroupPath(m.Cgroups)
	if err != nil {
		return nil, err
	}
	return cgroups.GetAllPids(dir)
}

func (m *Manager) GetStats() (*cgroups.Stats, error) {
	// We can just use the fs manager to get the appropriate stats.
	otherm := fs.Manager{
		Cgroups: m.Cgroups,
		Paths:   m.Paths,
	}
	return otherm.GetStats()
}

func (m *Manager) Freeze(state configs.FreezerState) error {
	// TODO(cyphar): We can make this work if we figure out a way to allow usage
	//               of cgroups with a rootless container.
	return fmt.Errorf("cannot use freezer cgroup in rootless container")
}

func (m *Manager) Destroy() error {
	// We don't have to do anything here because we didn't do any setup.
	return nil
}
