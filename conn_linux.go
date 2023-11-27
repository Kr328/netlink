//go:build linux
// +build linux

package netlink

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

var _ Socket = &conn{}

// A conn is the Linux implementation of a netlink sockets connection.
type conn struct {
	f *os.File
}

// dial is the entry point for Dial. dial opens a netlink socket using
// system calls, and returns its PID.
func dial(family int, config *Config) (*conn, uint32, error) {
	if config == nil {
		config = &Config{}
	}

	// Prepare the netlink socket.
	s, err := unix.Socket(
		unix.AF_NETLINK,
		unix.SOCK_RAW,
		family,
	)
	if err != nil {
		return nil, 0, fmt.Errorf("socket: %w", err)
	}

	err = unix.SetNonblock(s, true)
	if err != nil {
		return nil, 0, fmt.Errorf("set nonblock failed: %w", err)
	}

	f := os.NewFile(uintptr(s), "socket")
	return newConn(f, config)
}

// newConn binds a connection to netlink using the input *socket.Conn.
func newConn(f *os.File, config *Config) (*conn, uint32, error) {
	if config == nil {
		config = &Config{}
	}

	addr := &unix.SockaddrNetlink{
		Family: unix.AF_NETLINK,
		Groups: config.Groups,
		Pid:    config.PID,
	}

	// Socket must be closed in the event of any system call errors, to avoid
	// leaking file descriptors.

	if _, err := sysFn(f, sysControl, "bind", func(fd int) (struct{}, error) {
		return struct{}{}, unix.Bind(fd, addr)
	}); err != nil {
		_ = f.Close()
		return nil, 0, err
	}

	sa, err := sysFn(f, sysControl, "getsockname", func(fd int) (unix.Sockaddr, error) {
		return unix.Getsockname(fd)
	})
	if err != nil {
		_ = f.Close()
		return nil, 0, err
	}

	c := &conn{f: f}
	if config.Strict {
		// The caller has requested the strict option set. Historically we have
		// recommended checking for ENOPROTOOPT if the kernel does not support
		// the option in question, but that may result in a silent failure and
		// unexpected behavior for the user.
		//
		// Treat any error here as a fatal error, and require the caller to deal
		// with it.
		for _, o := range []ConnOption{ExtendedAcknowledge, GetStrictCheck} {
			if err := c.SetOption(o, true); err != nil {
				_ = c.Close()
				return nil, 0, err
			}
		}
	}

	return c, sa.(*unix.SockaddrNetlink).Pid, nil
}

// SendMessages serializes multiple Messages and sends them to netlink.
func (c *conn) SendMessages(messages []Message) error {
	var datas [][]byte
	for _, message := range messages {
		datas = append(
			datas,
			unsafe.Slice((*byte)(unsafe.Pointer(&message.Header)), int(unsafe.Sizeof(message.Header))),
			message.Data,
		)
	}

	_, err := sysFn(c.f, sysWrite, "sendmsg", func(fd int) (int, error) {
		return unix.SendmsgBuffers(fd, datas, nil, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}, 0)
	})
	return err
}

// Send sends a single Message to netlink.
func (c *conn) Send(m Message) error {
	return c.SendMessages([]Message{m})
}

// Receive receives one or more Messages from netlink.
func (c *conn) Receive() ([]Message, error) {
	n, err := sysFn(c.f, sysRead, "recvmsg", func(fd int) (int, error) {
		n, _, _, _, err := unix.Recvmsg(fd, nil, nil, unix.MSG_PEEK|unix.MSG_TRUNC)
		return n, err
	})
	if err != nil {
		return nil, err
	}

	b := make([]byte, n)
	_, err = sysFn(c.f, sysRead, "recvmsg", func(fd int) (int, error) {
		n, _, _, _, err := unix.Recvmsg(fd, b, nil, unix.MSG_TRUNC)
		return n, err
	})
	if err != nil {
		return nil, err
	}

	raw, err := syscall.ParseNetlinkMessage(b[:nlmsgAlign(n)])
	if err != nil {
		return nil, err
	}

	msgs := make([]Message, 0, len(raw))
	for _, r := range raw {
		m := Message{
			Header: sysToHeader(r.Header),
			Data:   r.Data,
		}

		msgs = append(msgs, m)
	}

	return msgs, nil
}

// Close closes the connection.
func (c *conn) Close() error { return c.f.Close() }

// JoinGroup joins a multicast group by ID.
func (c *conn) JoinGroup(group uint32) error {
	_, err := sysFn(c.f, sysControl, "setsockopt", func(fd int) (struct{}, error) {
		return struct{}{}, unix.SetsockoptInt(fd, unix.SOL_NETLINK, unix.NETLINK_ADD_MEMBERSHIP, int(group))
	})
	return err
}

// LeaveGroup leaves a multicast group by ID.
func (c *conn) LeaveGroup(group uint32) error {
	_, err := sysFn(c.f, sysControl, "setsockopt", func(fd int) (struct{}, error) {
		return struct{}{}, unix.SetsockoptInt(fd, unix.SOL_NETLINK, unix.NETLINK_DROP_MEMBERSHIP, int(group))
	})
	return err
}

//// SetBPF attaches an assembled BPF program to a conn.
//func (c *conn) SetBPF(filter []bpf.RawInstruction) error {
//	return c.f.SetBPF(filter)
//}
//
//// RemoveBPF removes a BPF filter from a conn.
//func (c *conn) RemoveBPF() error { return c.f.RemoveBPF() }

// SetOption enables or disables a netlink socket option for the Conn.
func (c *conn) SetOption(option ConnOption, enable bool) error {
	o, ok := linuxOption(option)
	if !ok {
		// Return the typical Linux error for an unknown ConnOption.
		return os.NewSyscallError("setsockopt", unix.ENOPROTOOPT)
	}

	var v int
	if enable {
		v = 1
	}

	_, err := sysFn(c.f, sysControl, "setsockopt", func(fd int) (struct{}, error) {
		return struct{}{}, unix.SetsockoptInt(fd, unix.SOL_NETLINK, o, v)
	})
	return err
}

func (c *conn) SetDeadline(t time.Time) error      { return c.f.SetDeadline(t) }
func (c *conn) SetReadDeadline(t time.Time) error  { return c.f.SetReadDeadline(t) }
func (c *conn) SetWriteDeadline(t time.Time) error { return c.f.SetWriteDeadline(t) }

// SetReadBuffer sets the size of the operating system's receive buffer
// associated with the Conn.
func (c *conn) SetReadBuffer(bytes int) error {
	_, err := sysFn(c.f, sysControl, "setsockopt", func(fd int) (struct{}, error) {
		return struct{}{}, unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, bytes)
	})
	return err
}

// SetReadBuffer sets the size of the operating system's transmit buffer
// associated with the Conn.
func (c *conn) SetWriteBuffer(bytes int) error {
	_, err := sysFn(c.f, sysControl, "setsockopt", func(fd int) (struct{}, error) {
		return struct{}{}, unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, bytes)
	})
	return err
}

// SyscallConn returns a raw network connection.
func (c *conn) SyscallConn() (syscall.RawConn, error) { return c.f.SyscallConn() }

// linuxOption converts a ConnOption to its Linux value.
func linuxOption(o ConnOption) (int, bool) {
	switch o {
	case PacketInfo:
		return unix.NETLINK_PKTINFO, true
	case BroadcastError:
		return unix.NETLINK_BROADCAST_ERROR, true
	case NoENOBUFS:
		return unix.NETLINK_NO_ENOBUFS, true
	case ListenAllNSID:
		return unix.NETLINK_LISTEN_ALL_NSID, true
	case CapAcknowledge:
		return unix.NETLINK_CAP_ACK, true
	case ExtendedAcknowledge:
		return unix.NETLINK_EXT_ACK, true
	case GetStrictCheck:
		return unix.NETLINK_GET_STRICT_CHK, true
	default:
		return 0, false
	}
}

// sysToHeader converts a syscall.NlMsghdr to a Header.
func sysToHeader(r syscall.NlMsghdr) Header {
	// NB: the memory layout of Header and syscall.NlMsgHdr must be
	// exactly the same for this unsafe cast to work
	return *(*Header)(unsafe.Pointer(&r))
}

// newError converts an error number from netlink into the appropriate
// system call error for Linux.
func newError(errno int) error {
	return syscall.Errno(errno)
}

const (
	sysRead = iota
	sysWrite
	sysControl
)

func sysFn[T any](f *os.File, sop int, op string, fn func(fd int) (T, error)) (T, error) {
	var value T

	sc, err := f.SyscallConn()
	if err != nil {
		return value, err
	}

	var innerErr error
	switch sop {
	case sysRead, sysWrite:
		f := func(fd uintptr) (done bool) {
			value, innerErr = fn(int(fd))
			if errors.Is(innerErr, unix.EAGAIN) || errors.Is(innerErr, unix.EINTR) {
				return false
			}

			return true
		}

		if sop == sysRead {
			err = sc.Read(f)
		} else {
			err = sc.Write(f)
		}
	case sysControl:
		err = sc.Control(func(fd uintptr) {
			value, innerErr = fn(int(fd))
		})
	}
	if err != nil {
		return value, err
	} else if innerErr != nil {
		return value, fmt.Errorf("%s: %w", op, innerErr)
	}

	return value, nil
}
