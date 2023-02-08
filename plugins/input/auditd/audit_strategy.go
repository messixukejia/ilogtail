// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

//go:build !windows
// +build !windows

package auditd

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/elastic/go-libaudit/v2"
	"github.com/elastic/go-libaudit/v2/auparse"
)

func kernelVersion() (major, minor int, full string, err error) {
	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err != nil {
		return 0, 0, "", err
	}

	length := len(uname.Release)
	data := make([]byte, length)
	for i, v := range uname.Release {
		if v == 0 {
			length = i
			break
		}
		data[i] = byte(v)
	}

	release := string(data[:length])
	parts := strings.SplitN(release, ".", 3)
	if len(parts) < 2 {
		return 0, 0, release, fmt.Errorf("failed to parse uname release '%v'", release)
	}

	major, err = strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, release, fmt.Errorf("failed to parse major version from '%v': %w", release, err)
	}

	minor, err = strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, release, fmt.Errorf("failed to parse minor version from '%v': %w", release, err)
	}

	return major, minor, release, nil
}

func failureMode(mode string) (uint32, error) {
	switch strings.ToLower(mode) {
	case "silent":
		return 0, nil
	case "log":
		return 1, nil
	case "panic":
		return 2, nil
	default:
		return 0, fmt.Errorf("invalid failure_mode '%v' (use silent, log, or panic)", mode)
	}
}

func getBackpressureStrategy(value string) backpressureStrategy {
	switch value {
	case "auto":
		return bsAuto
	case "kernel":
		return bsKernel
	case "userspace":
		return bsUserSpace
	case "both":
		return bsKernel | bsUserSpace
	default:
		return 0
	}
}

func filterRecordType(typ auparse.AuditMessageType) bool {
	switch {
	// REPLACE messages are tests to check if Auditbeat is still healthy by
	// seeing if unicast messages can be sent without error from the kernel.
	// Ignore them.
	case typ == auparse.AUDIT_REPLACE:
		return true
	// Messages from 1300-2999 are valid audit message types.
	case (typ < auparse.AUDIT_USER_AUTH || typ > auparse.AUDIT_LAST_USER_MSG2) && typ != auparse.AUDIT_LOGIN:
		return true
	}

	return false
}

func newAuditClient(sockType string) (*libaudit.AuditClient, error) {
	if sockType == multicast {
		return libaudit.NewMulticastAuditClient(nil)
	}
	return libaudit.NewAuditClient(nil)
}

func closeAuditClient(client *libaudit.AuditClient) error {
	discard := func(bytes []byte) ([]syscall.NetlinkMessage, error) {
		return nil, nil
	}
	// Drain the netlink channel in parallel to Close() to prevent a deadlock.
	// This goroutine will terminate once receive from netlink errors (EBADF,
	// EBADFD, or any other error). This happens because the fd is closed.
	go func() {
		for {
			_, err := client.Netlink.Receive(true, discard)
			switch {
			case err == nil, errors.Is(err, syscall.EINTR):
			case errors.Is(err, syscall.EAGAIN):
				time.Sleep(50 * time.Millisecond)
			default:
				return
			}
		}
	}()
	if err := client.Close(); err != nil {
		return fmt.Errorf("Error closing audit monitoring client %w", err)
	}
	return nil
}
