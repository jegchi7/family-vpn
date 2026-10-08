//go:build linux

package netstand

import (
	"io"
	"os"

	"golang.org/x/sys/unix"
)

type operation struct {
	parent int
	file   *os.File
	stat   unix.Stat_t
	state  journalState
	length int64
}

func journalFile(s unix.Stat_t, allowEmpty bool) bool {
	return s.Uid == 0 && s.Mode&unix.S_IFMT == unix.S_IFREG && s.Mode&07777 == 0600 && s.Nlink == 1 && s.Size <= journalLimit && (s.Size > 0 || allowEmpty && s.Size == 0)
}
func journalParent(fd int) error {
	var s unix.Stat_t
	if unix.Fstat(fd, &s) != nil || !protectedDir(s, true) {
		return ErrProtected
	}
	return nil
}
func beginOperation(stagefd int, binding string) (*operation, error) {
	if !digestValid(binding) || journalParent(stagefd) != nil {
		return nil, ErrProtected
	}
	parent, e := unix.FcntlInt(uintptr(stagefd), unix.F_DUPFD_CLOEXEC, 0)
	if e != nil {
		return nil, ErrProtected
	}
	fd, e := unix.Openat(parent, journalName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_APPEND|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
	if e != nil {
		unix.Close(parent)
		if e == unix.EEXIST {
			return nil, ErrRecovery
		}
		return nil, ErrProtected
	}
	f := os.NewFile(uintptr(fd), "private-network-operation")
	var s unix.Stat_t
	// Never remove a created fence, including on cancellation/write failure.
	if unix.Fchmod(fd, 0600) != nil || unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB) != nil || unix.Fstat(fd, &s) != nil || !journalFile(s, true) {
		f.Close()
		unix.Close(parent)
		return nil, ErrProtected
	}
	op := &operation{parent: parent, file: f, stat: s}
	if e := op.writeRecord(binding, 0, "progress"); e != nil {
		op.close()
		return nil, e
	}
	if unix.Fsync(parent) != nil {
		op.close()
		return nil, ErrProtected
	}
	return op, nil
}
func (o *operation) check() error {
	if o == nil || o.file == nil || o.parent < 0 || journalParent(o.parent) != nil {
		return ErrProtected
	}
	var actual unix.Stat_t
	if unix.Fstat(int(o.file.Fd()), &actual) != nil || !same(actual, o.stat) || !journalFile(actual, o.length == 0) || unix.Fstatat(o.parent, journalName, &actual, unix.AT_SYMLINK_NOFOLLOW) != nil || !same(actual, o.stat) {
		return ErrProtected
	}
	return nil
}
func (o *operation) writeRecord(binding string, completed int, state string) error {
	if o.check() != nil {
		return ErrProtected
	}
	r, e := nextRecord(o.state, binding, completed, state)
	if e != nil {
		return e
	}
	b, e := journalBytes(r)
	if e != nil || o.length+int64(len(b)) > journalLimit {
		return ErrRecovery
	}
	n, e := o.file.Write(b)
	if e != nil || n != len(b) || o.file.Sync() != nil {
		return ErrProtected
	}
	var actual unix.Stat_t
	if unix.Fstat(int(o.file.Fd()), &actual) != nil || !journalFile(actual, false) || actual.Dev != o.stat.Dev || actual.Ino != o.stat.Ino || actual.Uid != o.stat.Uid || actual.Gid != o.stat.Gid || actual.Mode != o.stat.Mode || actual.Nlink != o.stat.Nlink || actual.Size != o.length+int64(len(b)) {
		return ErrProtected
	}
	o.stat = actual
	o.length = actual.Size
	o.state = recordState(r)
	if o.check() != nil {
		return ErrProtected
	}
	return nil
}
func (o *operation) record(completed int, state string) error {
	if o == nil {
		return ErrProtected
	}
	return o.writeRecord(o.state.binding, completed, state)
}
func (o *operation) close() {
	if o != nil {
		if o.file != nil {
			o.file.Close()
			o.file = nil
		}
		if o.parent >= 0 {
			unix.Close(o.parent)
			o.parent = -1
		}
	}
}
func readJournal(stagefd int) (journalState, error) {
	if journalParent(stagefd) != nil {
		return journalState{}, ErrProtected
	}
	var before, after unix.Stat_t
	if unix.Fstatat(stagefd, journalName, &before, unix.AT_SYMLINK_NOFOLLOW) != nil || !journalFile(before, false) {
		return journalState{}, ErrRecovery
	}
	fd, e := unix.Openat(stagefd, journalName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if e != nil {
		return journalState{}, ErrRecovery
	}
	f := os.NewFile(uintptr(fd), "private-network-operation")
	defer f.Close()
	if unix.Flock(fd, unix.LOCK_SH|unix.LOCK_NB) != nil || unix.Fstat(fd, &after) != nil || !same(before, after) {
		return journalState{}, ErrRecovery
	}
	data, e := io.ReadAll(io.LimitReader(f, journalLimit+1))
	if e != nil || int64(len(data)) != before.Size || unix.Fstat(fd, &after) != nil || !same(before, after) || unix.Fstatat(stagefd, journalName, &after, unix.AT_SYMLINK_NOFOLLOW) != nil || !same(before, after) || journalParent(stagefd) != nil {
		return journalState{}, ErrRecovery
	}
	state, e := validateJournalBytes(data)
	clear(data)
	return state, e
}
func validateJournal(stagefd int) error { _, e := readJournal(stagefd); return e }
func readOperation(stagefd int, binding string, steps int) error {
	if !digestValid(binding) || steps < 1 || steps > 64 {
		return ErrRecovery
	}
	s, e := readJournal(stagefd)
	if e != nil || s.binding != binding || s.completed != steps || s.state != "complete" {
		return ErrRecovery
	}
	return nil
}
