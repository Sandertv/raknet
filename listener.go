package raknet

import (
	"errors"
	"fmt"
	"github.com/sandertv/go-raknet/internal"
	"log/slog"
	"maps"
	"math"
	"math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// UpstreamPacketListener allows for a custom PacketListener implementation.
type UpstreamPacketListener interface {
	ListenPacket(network, address string) (net.PacketConn, error)
}

// ListenConfig may be used to pass additional configuration to a Listener.
type ListenConfig struct {
	// ErrorLog is a logger that errors from packet decoding are logged to. By
	// default, ErrorLog is set to a new slog.Logger with a slog.Handler that
	// is always disabled. Error messages are thus not logged by default.
	ErrorLog *slog.Logger

	// UpstreamPacketListener adds an abstraction for net.ListenPacket.
	UpstreamPacketListener UpstreamPacketListener

	// DisableCookies specifies if cookies should be generated and verified for
	// new incoming connections. This is a security measure against IP spoofing,
	// but some server providers (OVH in particular) have existing protection
	// systems that interfere with this. In this case, DisableCookies should be
	// set to true.
	DisableCookies bool
	// BlockDuration specifies how long IP addresses should be blocked if an
	// error is encountered during the handling of packets from an address.
	// BlockDuration defaults to 10s. If set to a negative value, IP addresses
	// are never blocked on errors.
	BlockDuration time.Duration
}

// Listener implements a RakNet connection listener. It follows the same
// methods as those implemented by the TCPListener in the net package. Listener
// implements the net.Listener interface.
type Listener struct {
	conf    ListenConfig
	handler *listenerConnectionHandler
	sec     *security

	once   sync.Once
	closed chan struct{}

	conn net.PacketConn
	// incoming is a channel of incoming connections. Connections that end up in
	// here will also end up in the connections map.
	incoming chan *Conn

	// connections is a map of currently active connections, indexed by their
	// address.
	connections sync.Map

	// id is a random server ID generated upon starting listening. It is used
	// several times throughout the connection sequence of RakNet.
	id int64

	// pongData is a byte slice of data that is sent in an unconnected pong
	// packet each time the client sends and unconnected ping to the server.
	pongData atomic.Pointer[[]byte]
}

// listenerID holds the next ID to use for a Listener.
var listenerID = rand.Int64()

// Listen listens on the address passed and returns a listener that may be used
// to accept connections. If not successful, an error is returned. The address
// follows the same rules as those defined in the net.TCPListen() function.
// Specific features of the listener may be modified once it is returned, such
// as the used log and/or the accepted protocol.
func (conf ListenConfig) Listen(address string) (*Listener, error) {
	if conf.ErrorLog == nil {
		conf.ErrorLog = slog.New(internal.DiscardHandler{})
	}
	conf.ErrorLog = conf.ErrorLog.With("src", "listener")

	if conf.BlockDuration == 0 {
		conf.BlockDuration = time.Second * 10
	}
	var conn net.PacketConn
	var err error

	if conf.UpstreamPacketListener == nil {
		conn, err = net.ListenPacket("udp", address)
	} else {
		conn, err = conf.UpstreamPacketListener.ListenPacket("udp", address)
	}
	if err != nil {
		return nil, &net.OpError{Op: "listen", Net: "raknet", Source: nil, Addr: nil, Err: err}
	}
	listener := &Listener{
		conf:     conf,
		conn:     conn,
		incoming: make(chan *Conn),
		closed:   make(chan struct{}),
		id:       atomic.AddInt64(&listenerID, 1),
		sec:      newSecurity(conf),
	}
	listener.handler = &listenerConnectionHandler{l: listener, cookieSalt: rand.Uint32()}
	listener.pongData.Store(new([]byte))

	go listener.listen()
	go listener.sec.gc(listener.closed)
	return listener, nil
}

// Listen listens on the address passed and returns a listener that may be used
// to accept connections. If not successful, an error is returned. The address
// follows the same rules as those defined in the net.TCPListen() function.
// Specific features of the listener may be modified once it is returned, such
// as the used log and/or the accepted protocol.
func Listen(address string) (*Listener, error) {
	var lc ListenConfig
	return lc.Listen(address)
}

// Accept blocks until a connection can be accepted by the listener. If
// successful, Accept returns a connection that is ready to send and receive
// data. If not successful, a nil listener is returned and an error describing
// the problem.
func (listener *Listener) Accept() (net.Conn, error) {
	conn, ok := <-listener.incoming
	if !ok {
		return nil, &net.OpError{Op: "accept", Net: "raknet", Source: nil, Addr: nil, Err: ErrListenerClosed}
	}
	return conn, nil
}

// Addr returns the address the Listener is bound to and listening for
// connections on.
func (listener *Listener) Addr() net.Addr {
	return listener.conn.LocalAddr()
}

// Close closes the listener so that it may be cleaned up. It makes sure the
// goroutine handling incoming packets is able to be freed.
func (listener *Listener) Close() error {
	var err error
	listener.once.Do(func() {
		close(listener.closed)
		err = listener.conn.Close()
	})
	return err
}

// PongData sets the pong data that is used to respond with when a client sends
// a ping. It usually holds game specific data that is used to display in a
// server list. If a data slice is set with a size bigger than math.MaxInt16,
// the function panics.
func (listener *Listener) PongData(data []byte) {
	if len(data) > math.MaxInt16 {
		panic(fmt.Sprintf("pong data: must be no longer than %v bytes, got %v", math.MaxInt16, len(data)))
	}
	listener.pongData.Store(&data)
}

// ID returns the unique ID of the listener. This ID is usually used by a
// client to identify a specific server during a single session.
func (listener *Listener) ID() int64 {
	return listener.id
}

// listen continuously reads from the listener's UDP connection, until closed
// has a value in it.
func (listener *Listener) listen() {
	// Create a buffer with the maximum size a UDP packet sent over RakNet is
	// allowed to have. We can re-use this buffer for each packet.
	b := make([]byte, 1500)
	for {
		n, addr, err := listener.conn.ReadFrom(b)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				close(listener.incoming)
				return
			}
			listener.conf.ErrorLog.Error("read from: " + err.Error())
			continue
		} else if n == 0 || listener.sec.blocked(addr) {
			continue
		}
		if err = listener.handle(b[:n], addr); err != nil && !errors.Is(err, net.ErrClosed) {
			listener.conf.ErrorLog.Error("handle packet: "+err.Error(), "raddr", addr.String(), "block-duration", max(0, listener.conf.BlockDuration))
			listener.sec.block(addr)
		}
	}
}

// handle handles an incoming packet in buffer b from the address passed. If
// not successful, an error is returned describing the issue.
func (listener *Listener) handle(b []byte, addr net.Addr) error {
	value, found := listener.connections.Load(resolve(addr))
	if !found {
		return listener.handler.handleUnconnected(b, addr)
	}
	conn := value.(*Conn)
	select {
	case <-conn.ctx.Done():
		// Connection was closed already.
		return nil
	default:
		if err := conn.receive(b); err != nil {
			conn.closeImmediately()
			return err
		}
		return nil
	}
}

// security implements security measurements against DoS attacks against a
// Listener.
type security struct {
	conf ListenConfig

	blockCount atomic.Uint32

	mu     sync.Mutex
	blocks map[[16]byte]time.Time
}

// newSecurity uses settings from a ListenConfig to create a security.
func newSecurity(conf ListenConfig) *security {
	return &security{conf: conf, blocks: make(map[[16]byte]time.Time)}
}

// gc clears garbage from the security layer every second until the stop channel
// passed is closed.
func (s *security) gc(stop <-chan struct{}) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.gcBlocks()
		case <-stop:
			return
		}
	}
}

// block stops the handling of packets originating from the IP of a net.Addr.
func (s *security) block(addr net.Addr) {
	if s.conf.BlockDuration < 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	s.blockCount.Add(1)
	s.blocks[[16]byte(addr.(*net.UDPAddr).IP.To16())] = time.Now()
}

// blocked checks if the IP of a net.Addr is currently blocked from any packet
// handling.
func (s *security) blocked(addr net.Addr) bool {
	if s.conf.BlockDuration < 0 || s.blockCount.Load() == 0 {
		// Fast path optimisation: Prevents (relatively costly) map lookups.
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	_, blocked := s.blocks[[16]byte(addr.(*net.UDPAddr).IP.To16())]
	return blocked
}

// gcBlocks removes blocks from the map that are no longer active. gcBlocks only
// attempts to clear outdated blocks if there are two times more blocks active
// than there were after the previous call to gcBlocks.
func (s *security) gcBlocks() {
	if s.blockCount.Load() == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	maps.DeleteFunc(s.blocks, func(ip [16]byte, t time.Time) bool {
		return now.Sub(t) > s.conf.BlockDuration
	})
	s.blockCount.Store(uint32(len(s.blocks)))
}
