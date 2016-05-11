// +build linux

package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"syscall"
	"text/tabwriter"
	"time"

	"encoding/json"

	"github.com/opencontainers/runc/libcontainer/user"
	"github.com/opencontainers/runc/libcontainer/utils"
	"github.com/urfave/cli"
)

const formatOptions = `table(default) or json`

// containerState represents the platform agnostic pieces relating to a
// running container's status and state
type containerState struct {
	// ID is the container ID
	ID string `json:"id"`
	// InitProcessPid is the init process id in the parent namespace
	InitProcessPid int `json:"pid"`
	// Status is the current status of the container, running, paused, ...
	Status string `json:"status"`
	// Bundle is the path on the filesystem to the bundle
	Bundle string `json:"bundle"`
	// Created is the unix timestamp for the creation time of the container in UTC
	Created time.Time `json:"created"`
	// Annotations is the user defined annotations added to the config.
	Annotations map[string]string `json:"annotations,omitempty"`
	// The owner of the state directory (the owner of the container).
	Owner string `json:"owner"`
}

var listCommand = cli.Command{
	Name:  "list",
	Usage: "lists containers started by runc with the given root",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "format, f",
			Value: "",
			Usage: `select one of: ` + formatOptions,
		},
		cli.BoolFlag{
			Name:  "quiet, q",
			Usage: "display only container IDs",
		},
	},
	Action: func(context *cli.Context) error {
		s, err := getContainers(context)
		if err != nil {
			return err
		}

		if context.Bool("quiet") {
			for _, item := range s {
				fmt.Println(item.ID)
			}
			return nil
		}

		switch context.String("format") {
		case "", "table":
			w := tabwriter.NewWriter(os.Stdout, 12, 1, 3, ' ', 0)
			fmt.Fprint(w, "ID\tPID\tSTATUS\tBUNDLE\tCREATED\tOWNER\n")
			for _, item := range s {
				fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\t%s\n",
					item.ID,
					item.InitProcessPid,
					item.Status,
					item.Bundle,
					item.Created.Format(time.RFC3339Nano),
					item.Owner)
			}
			if err := w.Flush(); err != nil {
				return err
			}
		case "json":
			if err := json.NewEncoder(os.Stdout).Encode(s); err != nil {
				return err
			}
		default:
			return fmt.Errorf("invalid format option")
		}
		return nil
	},
}

func getContainers(context *cli.Context) ([]containerState, error) {
	factory, err := loadFactory(context)
	if err != nil {
		return nil, err
	}
	root := context.GlobalString("root")
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	list, err := ioutil.ReadDir(absRoot)
	if err != nil {
		fatal(err)
	}

	var s []containerState
	for _, item := range list {
		if item.IsDir() {
			// This cast is safe on Linux.
			stat := item.Sys().(*syscall.Stat_t)
			owner, err := user.LookupUid(int(stat.Uid))
			if err != nil {
				owner.Name = string(stat.Uid)
			}

			container, err := factory.Load(item.Name())
			if err != nil {
				// We can't error out here, because the current user may not
				// have access to the container.
				s = append(s, containerState{
					ID:             item.Name(),
					InitProcessPid: -1,
					Status:         "-",
					Bundle:         "-",
					Owner:          owner.Name,
				})
				continue
			}
			containerStatus, err := container.Status()
			if err != nil {
				return nil, err
			}
			state, err := container.State()
			if err != nil {
				return nil, err
			}
			bundle, annotations := utils.Annotations(state.Config.Labels)
			s = append(s, containerState{
				ID:             state.BaseState.ID,
				InitProcessPid: state.BaseState.InitProcessPid,
				Status:         containerStatus.String(),
				Bundle:         bundle,
				Created:        state.BaseState.Created,
				Annotations:    annotations,
				Owner:          owner.Name,
			})
		}
	}
	return s, nil
}
