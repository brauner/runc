package validate

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/opencontainers/runc/libcontainer/configs"
)

type RootlessValidator struct {
}

func (v *RootlessValidator) Validate(config *configs.Config) error {
	// There's nothing to validate.
	if config == nil {
		return nil
	}

	if err := v.mount(config); err != nil {
		return err
	}
	// Currently, cgroups cannot effectively be used in rootless containers.
	// However, in Linux >=4.6 this may no longer be the case due to the
	// cgroup namespace being merged.
	if err := v.cgroup(config); err != nil {
		return err
	}

	// XXX: We currently can't verify the user config at all, because
	//      configs.Config doesn't store the user-related configs. So this
	//      has to be verified by setupUser() in init_linux.go.

	return nil
}

// cgroup verifies that the user isn't trying to set any cgroup limits or paths.
func (v *RootlessValidator) cgroup(config *configs.Config) error {
	// Nothing set at all.
	if config.Cgroups == nil || config.Cgroups.Resources == nil {
		return nil
	}

	// Used for comparison.
	left := reflect.ValueOf(*config.Cgroups.Resources)
	right := reflect.Zero(left.Type())

	// Unfortunately this isn't all we need to do, because at this point specconv
	// has already added a bunch of rules to the devices cgroup. So we have to
	// check against each field separately.
	if reflect.DeepEqual(left.Interface(), right.Interface()) {
		return nil
	}

	// Iterate over the fields of each resource.
	for i := 0; i < left.NumField(); i++ {
		name := left.Type().Field(i).Name

		// XXX: I'm not sure what to do with device cgroups.
		if strings.Contains(name, "Device") {
			continue
		}

		// Get the field values.
		l := left.FieldByName(name)
		r := right.FieldByName(name)

		// Check that they are equal.
		if !reflect.DeepEqual(l.Interface(), r.Interface()) {
			return fmt.Errorf("cannot specify resource limits in rootless container: field %q is non-default", name)
		}
	}

	return nil
}

// mount verifies that the user isn't trying to set up any mounts they don't have
// the rights to do. In addition, it makes sure that no mount has a `uid=` or
// `gid=` option that doesn't resolve to root.
func (v *RootlessValidator) mount(config *configs.Config) error {
	// XXX: We could whitelist allowed devices at this point, but I'm not
	//      convinced that's a good idea. The kernel is the best arbiter of
	//      access control.

	for _, mount := range config.Mounts {
		// Check that the options list doesn't contain any uid= or gid= entries
		// that don't resolve to root.
		for _, opt := range strings.Split(mount.Data, ",") {
			if strings.HasPrefix(opt, "uid=") && opt != "uid=0" {
				return fmt.Errorf("cannot specify uid= mount options in rootless containers where argument isn't 0")
			}
			if strings.HasPrefix(opt, "gid=") && opt != "gid=0" {
				return fmt.Errorf("cannot specify gid= mount options in rootless containers where argument isn't 0")
			}
		}
	}

	return nil
}
