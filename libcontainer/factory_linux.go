// +build linux

package libcontainer

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strconv"
	"syscall"

	"github.com/docker/docker/pkg/mount"
	"github.com/opencontainers/runc/libcontainer/cgroups"
	"github.com/opencontainers/runc/libcontainer/cgroups/fs"
	"github.com/opencontainers/runc/libcontainer/cgroups/rootless"
	"github.com/opencontainers/runc/libcontainer/cgroups/systemd"
	"github.com/opencontainers/runc/libcontainer/configs"
	"github.com/opencontainers/runc/libcontainer/configs/validate"
	"github.com/opencontainers/runc/libcontainer/utils"
)

const (
	stateFilename = "state.json"
)

var (
	idRegex  = regexp.MustCompile(`^[\w+-\.]+$`)
	maxIdLen = 1024
)

// InitArgs returns an options func to configure a LinuxFactory with the
// provided init arguments.
func InitArgs(args ...string) func(*LinuxFactory) error {
	return func(l *LinuxFactory) error {
		name := args[0]
		if filepath.Base(name) == name {
			if lp, err := exec.LookPath(name); err == nil {
				name = lp
			}
		} else {
			abs, err := filepath.Abs(name)
			if err != nil {
				return err
			}
			name = abs
		}
		l.InitPath = "/proc/self/exe"
		l.InitArgs = append([]string{name}, args[1:]...)
		return nil
	}
}

// InitPath returns an options func to configure a LinuxFactory with the
// provided absolute path to the init binary and arguements.
func InitPath(path string, args ...string) func(*LinuxFactory) error {
	return func(l *LinuxFactory) error {
		l.InitPath = path
		l.InitArgs = args
		return nil
	}
}

// SystemdCgroups is an options func to configure a LinuxFactory to return
// containers that use systemd to create and manage cgroups.
func SystemdCgroups(l *LinuxFactory) error {
	l.NewCgroupsManager = func(config *configs.Cgroup, paths map[string]string) cgroups.Manager {
		return &systemd.Manager{
			Cgroups: config,
			Paths:   paths,
		}
	}
	return nil
}

// Cgroupfs is an options func to configure a LinuxFactory to return
// containers that use the native cgroups filesystem implementation to
// create and manage cgroups.
func Cgroupfs(l *LinuxFactory) error {
	l.NewCgroupsManager = func(config *configs.Cgroup, paths map[string]string) cgroups.Manager {
		return &fs.Manager{
			Cgroups: config,
			Paths:   paths,
		}
	}
	return nil
}

// RootlessCgroups is an options func to configure a LinuxFactory to
// return containers that use the "rootless" cgroup manager, which will
// fail to do any operations not possible to do with an unprivileged user.
// It should only be used in conjunction with rootless containers.
func RootlessCgroups(l *LinuxFactory) error {
	l.NewCgroupsManager = func(config *configs.Cgroup, paths map[string]string) cgroups.Manager {
		return &rootless.Manager{
			Cgroups: config,
			Paths:   paths,
		}
	}
	return nil
}

// TmpfsRoot is an option func to mount LinuxFactory.Root to tmpfs.
func TmpfsRoot(l *LinuxFactory) error {
	mounted, err := mount.Mounted(l.Root)
	if err != nil {
		return err
	}
	if !mounted {
		if err := syscall.Mount("tmpfs", l.Root, "tmpfs", 0, ""); err != nil {
			return err
		}
	}
	return nil
}

// New returns a linux based container factory based in the root directory and
// configures the factory with the provided option funcs.
func New(root string, options ...func(*LinuxFactory) error) (Factory, error) {
	if root != "" {
		if err := os.MkdirAll(root, 0700); err != nil {
			return nil, newGenericError(err, SystemError)
		}
	}
	l := &LinuxFactory{
		Root:      root,
		Validator: validate.New(),
		CriuPath:  "criu",
	}
	InitArgs(os.Args[0], "init")(l)
	Cgroupfs(l)
	for _, opt := range options {
		if err := opt(l); err != nil {
			return nil, err
		}
	}
	return l, nil
}

// LinuxFactory implements the default factory interface for linux based systems.
type LinuxFactory struct {
	// Root directory for the factory to store state.
	Root string

	// InitPath is the absolute path to the init binary.
	InitPath string

	// InitArgs are arguments for calling the init responsibilities for spawning
	// a container.
	InitArgs []string

	// CriuPath is the path to the criu binary used for checkpoint and restore of
	// containers.
	CriuPath string

	// Validator provides validation to container configurations.
	Validator validate.Validator

	// NewCgroupsManager returns an initialized cgroups manager for a single container.
	NewCgroupsManager func(config *configs.Cgroup, paths map[string]string) cgroups.Manager
}

func isRootless(config *configs.Config) (bool, error) {
	// There are two cases where we have to bail. If the user is trying to run
	// without user namespaces or if they are trying to run with user namespaces
	// where the remapping isn't their own user. These only apply for non-root
	// users.
	rootless := false

	rootuid, err := config.HostUID()
	if err != nil {
		return false, err
	}
	if euid := os.Geteuid(); euid != 0 {
		if !config.Namespaces.Contains(configs.NEWUSER) {
			return false, fmt.Errorf("rootless containers require user namespaces")
		}
		if rootuid != euid {
			return false, fmt.Errorf("rootless containers cannot map container root to a different host user")
		}
		// Thus, we are going to be running under unprivileged user namespaces.
		rootless = true
	}
	rootgid, err := config.HostGID()
	if err != nil {
		return false, err
	}
	// Similar to the above test, we need to make sure that we aren't trying to
	// map to a group ID that we don't have the right to be.
	if rootless && rootgid != os.Getegid() {
		return false, fmt.Errorf("rootless containers cannot map container root to a different host group")
	}

	// We can only map one user and group inside a container (our own).
	if rootless {
		if len(config.UidMappings) != 1 || config.UidMappings[0].Size != 1 {
			return false, fmt.Errorf("rootless containers cannot map more than one user")
		}
		if len(config.GidMappings) != 1 || config.GidMappings[0].Size != 1 {
			return false, fmt.Errorf("rootless containers cannot map more than one group")
		}
	}

	return rootless, nil
}

func (l *LinuxFactory) Create(id string, config *configs.Config) (Container, error) {
	if l.Root == "" {
		return nil, newGenericError(fmt.Errorf("invalid root"), ConfigInvalid)
	}
	if err := l.validateID(id); err != nil {
		return nil, err
	}
	if err := l.Validator.Validate(config); err != nil {
		return nil, newGenericError(err, ConfigInvalid)
	}
	rootless, err := isRootless(config)
	if err != nil {
		return nil, newGenericError(err, ConfigInvalid)
	}
	if rootless {
		if err := new(validate.RootlessValidator).Validate(config); err != nil {
			return nil, newGenericError(err, ConfigInvalid)
		}
	}
	containerRoot := filepath.Join(l.Root, id)
	if _, err := os.Stat(containerRoot); err == nil {
		return nil, newGenericError(fmt.Errorf("container with id exists: %v", id), IdInUse)
	} else if !os.IsNotExist(err) {
		return nil, newGenericError(err, SystemError)
	}
	if err := os.MkdirAll(containerRoot, 0700); err != nil {
		return nil, newGenericError(err, SystemError)
	}
	if rootless {
		RootlessCgroups(l)
	}
	c := &linuxContainer{
		id:            id,
		root:          containerRoot,
		config:        config,
		initPath:      l.InitPath,
		initArgs:      l.InitArgs,
		criuPath:      l.CriuPath,
		cgroupManager: l.NewCgroupsManager(config.Cgroups, nil),
		rootless:      rootless,
	}
	c.state = &stoppedState{c: c}
	return c, nil
}

func (l *LinuxFactory) Load(id string) (Container, error) {
	if l.Root == "" {
		return nil, newGenericError(fmt.Errorf("invalid root"), ConfigInvalid)
	}
	containerRoot := filepath.Join(l.Root, id)
	state, err := l.loadState(containerRoot)
	if err != nil {
		return nil, err
	}
	r := &nonChildProcess{
		processPid:       state.InitProcessPid,
		processStartTime: state.InitProcessStartTime,
		fds:              state.ExternalDescriptors,
	}
	c := &linuxContainer{
		initProcess:   r,
		id:            id,
		config:        &state.Config,
		initPath:      l.InitPath,
		initArgs:      l.InitArgs,
		criuPath:      l.CriuPath,
		cgroupManager: l.NewCgroupsManager(state.Config.Cgroups, state.CgroupPaths),
		root:          containerRoot,
		created:       state.Created,
		rootless:      state.Rootless,
	}
	c.state = &loadedState{c: c}
	if err := c.refreshState(); err != nil {
		return nil, err
	}
	return c, nil
}

func (l *LinuxFactory) Type() string {
	return "libcontainer"
}

// StartInitialization loads a container by opening the pipe fd from the parent to read the configuration and state
// This is a low level implementation detail of the reexec and should not be consumed externally
func (l *LinuxFactory) StartInitialization() (err error) {
	// start the signal handler as soon as we can
	s := make(chan os.Signal, 1)
	signal.Notify(s, InitContinueSignal)
	fdStr := os.Getenv("_LIBCONTAINER_INITPIPE")
	pipefd, err := strconv.Atoi(fdStr)
	if err != nil {
		return fmt.Errorf("error converting env var _LIBCONTAINER_INITPIPE(%q) to an int: %s", fdStr, err)
	}
	var (
		pipe = os.NewFile(uintptr(pipefd), "pipe")
		it   = initType(os.Getenv("_LIBCONTAINER_INITTYPE"))
	)
	// clear the current process's environment to clean any libcontainer
	// specific env vars.
	os.Clearenv()
	var i initer
	defer func() {
		// We have an error during the initialization of the container's init,
		// send it back to the parent process in the form of an initError.
		// If container's init successed, syscall.Exec will not return, hence
		// this defer function will never be called.
		if _, ok := i.(*linuxStandardInit); ok {
			//  Synchronisation only necessary for standard init.
			if err := utils.WriteJSON(pipe, syncT{procError}); err != nil {
				panic(err)
			}
		}
		if err := utils.WriteJSON(pipe, newSystemError(err)); err != nil {
			panic(err)
		}
		// ensure that this pipe is always closed
		pipe.Close()
	}()

	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("panic from initialization: %v, %v", e, string(debug.Stack()))
		}
	}()

	i, err = newContainerInit(it, pipe)
	if err != nil {
		return err
	}
	return i.Init(s)
}

func (l *LinuxFactory) loadState(root string) (*State, error) {
	f, err := os.Open(filepath.Join(root, stateFilename))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, newGenericError(err, ContainerNotExists)
		}
		return nil, newGenericError(err, SystemError)
	}
	defer f.Close()
	var state *State
	if err := json.NewDecoder(f).Decode(&state); err != nil {
		return nil, newGenericError(err, SystemError)
	}
	return state, nil
}

func (l *LinuxFactory) validateID(id string) error {
	if !idRegex.MatchString(id) {
		return newGenericError(fmt.Errorf("invalid id format: %v", id), InvalidIdFormat)
	}
	if len(id) > maxIdLen {
		return newGenericError(fmt.Errorf("invalid id format: %v", id), InvalidIdFormat)
	}
	return nil
}
