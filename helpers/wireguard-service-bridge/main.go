package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	routercommon "github.com/v2fly/v2ray-core/v5/app/router/routercommon"
	cnet "github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/common/packetswitch/gvisorstack"
	"github.com/v2fly/v2ray-core/v5/common/packetswitch/interconnect"
	"github.com/v2fly/v2ray-core/v5/proxy/wireguard/wgcommon"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
)

type config struct {
	Listen      string        `json:"listen"`
	PrivateKey  string        `json:"private_key"`
	MTU         int           `json:"mtu"`
	ServerCIDRs []string      `json:"server_cidrs"`
	Routes      []string      `json:"routes"`
	Peers       []peerConfig  `json:"peers"`
	Forwards    []forwardRule `json:"forwards"`
}

type peerConfig struct {
	PublicKey            string   `json:"public_key"`
	PreSharedKey         string   `json:"preshared_key,omitempty"`
	AllowedIPs           []string `json:"allowed_ips"`
	PersistentKeepalive  int64    `json:"persistent_keepalive,omitempty"`
}

type forwardRule struct {
	Service string `json:"service"`
	Target  string `json:"target"`
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	if len(os.Args) != 3 || os.Args[1] != "--config" {
		log.Fatalf("usage: %s --config /path/to/config.json", os.Args[0])
	}

	cfg, err := loadConfig(os.Args[2])
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	baseCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithCancel(baseCtx)
	defer cancel()
	go func() {
		_, _ = io.Copy(io.Discard, os.Stdin)
		cancel()
	}()

	if err := run(ctx, cfg); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatalf("wireguard bridge: %v", err)
	}
}

func loadConfig(path string) (*config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, err
	}

	if cfg.Listen == "" {
		return nil, errors.New("missing listen")
	}
	if cfg.PrivateKey == "" {
		return nil, errors.New("missing private_key")
	}
	if len(cfg.ServerCIDRs) == 0 {
		return nil, errors.New("missing server_cidrs")
	}
	if len(cfg.Peers) == 0 {
		return nil, errors.New("missing peers")
	}
	if len(cfg.Forwards) == 0 {
		return nil, errors.New("missing forwards")
	}
	if cfg.MTU <= 0 {
		cfg.MTU = 1400
	}

	for _, peer := range cfg.Peers {
		if peer.PublicKey == "" {
			return nil, errors.New("peer missing public_key")
		}
		if len(peer.AllowedIPs) == 0 {
			return nil, errors.New("peer missing allowed_ips")
		}
	}
	for _, forward := range cfg.Forwards {
		if forward.Service == "" || forward.Target == "" {
			return nil, errors.New("forward rules require service and target")
		}
		if _, err := netip.ParseAddrPort(forward.Service); err != nil {
			return nil, fmt.Errorf("invalid forward service %q: %w", forward.Service, err)
		}
		if _, err := net.ResolveTCPAddr("tcp", forward.Target); err != nil {
			return nil, fmt.Errorf("invalid forward target %q: %w", forward.Target, err)
		}
	}

	return &cfg, nil
}

func run(ctx context.Context, cfg *config) error {
	packetConn, err := net.ListenPacket("udp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen udp: %w", err)
	}
	defer packetConn.Close()

	cable, err := interconnect.NewNetworkLayerCable(ctx)
	if err != nil {
		return fmt.Errorf("new network cable: %w", err)
	}

	stackConfig, err := buildStackConfig(cfg)
	if err != nil {
		return err
	}

	stackWrapper, err := gvisorstack.NewStack(ctx, stackConfig)
	if err != nil {
		return fmt.Errorf("new gvisor stack: %w", err)
	}
	if err := stackWrapper.CreateStackFromNetworkLayerDevice(cable.GetRSideDevice()); err != nil {
		return fmt.Errorf("create gvisor stack: %w", err)
	}
	defer stackWrapper.Close()

	wgConfig, err := buildWireguardConfig(cfg, packetConn.LocalAddr())
	if err != nil {
		return err
	}

	device, err := wgcommon.NewWrappedWireguardDevice(ctx, wgConfig)
	if err != nil {
		return fmt.Errorf("new wireguard device: %w", err)
	}
	device.SetTunnel(cable.GetLSideDevice())
	device.SetConn(packetConn.(cnet.PacketConn))
	defer device.Close()

	if err := device.InitDevice(); err != nil {
		return fmt.Errorf("wireguard init: %w", err)
	}
	if err := device.SetupDeviceWithoutPeers(); err != nil {
		return fmt.Errorf("wireguard setup: %w", err)
	}
	if err := device.AddOrReplacePeers(wgConfig.GetPeers()); err != nil {
		return fmt.Errorf("wireguard peers: %w", err)
	}
	if err := device.Up(); err != nil {
		return fmt.Errorf("wireguard up: %w", err)
	}

	var wg sync.WaitGroup
	listeners := make([]*gonet.TCPListener, 0, len(cfg.Forwards))
	for _, forward := range cfg.Forwards {
		listener, err := createForwardListener(stackWrapper, forward.Service)
		if err != nil {
			return err
		}
		listeners = append(listeners, listener)
		wg.Add(1)
		go func(listener *gonet.TCPListener, target string) {
			defer wg.Done()
			acceptLoop(ctx, listener, target)
		}(listener, forward.Target)
		log.Printf("wireguard forward %s -> %s", forward.Service, forward.Target)
	}
	defer func() {
		for _, listener := range listeners {
			_ = listener.Close()
		}
		wg.Wait()
	}()

	log.Printf("wireguard bridge listening on %s", cfg.Listen)
	<-ctx.Done()
	return ctx.Err()
}

func buildStackConfig(cfg *config) (*gvisorstack.Config, error) {
	ips := make([]*routercommon.CIDR, 0, len(cfg.ServerCIDRs))
	hasIPv4 := false
	hasIPv6 := false
	for _, cidr := range cfg.ServerCIDRs {
		parsed, err := parseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("parse server cidr %q: %w", cidr, err)
		}
		if len(parsed.Ip) == net.IPv4len {
			hasIPv4 = true
		}
		if len(parsed.Ip) == net.IPv6len {
			hasIPv6 = true
		}
		ips = append(ips, parsed)
	}

	routes := make([]*routercommon.CIDR, 0, len(cfg.Routes)+2)
	if len(cfg.Routes) == 0 {
		if hasIPv4 {
			routes = append(routes, &routercommon.CIDR{Ip: []byte{0, 0, 0, 0}, Prefix: 0})
		}
		if hasIPv6 {
			routes = append(routes, &routercommon.CIDR{Ip: net.IPv6zero, Prefix: 0})
		}
	} else {
		for _, cidr := range cfg.Routes {
			parsed, err := parseCIDR(cidr)
			if err != nil {
				return nil, fmt.Errorf("parse route %q: %w", cidr, err)
			}
			routes = append(routes, parsed)
		}
	}

	return &gvisorstack.Config{
		Mtu:                  uint32(cfg.MTU),
		Ips:                  ips,
		Routes:               routes,
		EnablePromiscuousMode: false,
		EnableSpoofing:       false,
	}, nil
}

func buildWireguardConfig(cfg *config, addr net.Addr) (*wgcommon.DeviceConfig, error) {
	privateKey, err := decodeWGKey(cfg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("decode private_key: %w", err)
	}

	port, err := listenPort(addr)
	if err != nil {
		return nil, err
	}

	peers := make([]*wgcommon.PeerConfig, 0, len(cfg.Peers))
	for _, peer := range cfg.Peers {
		publicKey, err := decodeWGKey(peer.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("decode peer public_key: %w", err)
		}
		var preSharedKey []byte
		if peer.PreSharedKey != "" {
			preSharedKey, err = decodeWGKey(peer.PreSharedKey)
			if err != nil {
				return nil, fmt.Errorf("decode peer preshared_key: %w", err)
			}
		}
		peers = append(peers, &wgcommon.PeerConfig{
			PublicKey:                   publicKey,
			PresharedKey:                preSharedKey,
			AllowedIps:                  peer.AllowedIPs,
			PersistentKeepaliveInterval: peer.PersistentKeepalive,
		})
	}

	return &wgcommon.DeviceConfig{
		PrivateKey: privateKey,
		ListenPort: uint32(port),
		Peers:      peers,
		Mtu:        uint32(cfg.MTU),
	}, nil
}

func parseCIDR(value string) (*routercommon.CIDR, error) {
	ip, network, err := net.ParseCIDR(value)
	if err != nil {
		return nil, err
	}
	ip = normalizeIP(ip)
	if ip == nil {
		return nil, fmt.Errorf("unsupported ip %q", value)
	}
	prefix, _ := network.Mask.Size()
	return &routercommon.CIDR{
		Ip:     ip,
		Prefix: uint32(prefix),
	}, nil
}

func createForwardListener(stackWrapper *gvisorstack.WrappedStack, service string) (*gonet.TCPListener, error) {
	serviceAddr, err := netip.ParseAddrPort(service)
	if err != nil {
		return nil, fmt.Errorf("parse service %q: %w", service, err)
	}
	fullAddr := tcpip.FullAddress{
		Addr: tcpip.AddrFromSlice(serviceAddr.Addr().AsSlice()),
		Port: serviceAddr.Port(),
	}
	if serviceAddr.Addr().Is4() {
		return stackWrapper.CreateStackListener(fullAddr, ipv4.ProtocolNumber)
	}
	return stackWrapper.CreateStackListener(fullAddr, ipv6.ProtocolNumber)
}

func acceptLoop(ctx context.Context, listener *gonet.TCPListener, target string) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || strings.Contains(err.Error(), "closed") {
				return
			}
			log.Printf("wireguard accept error on %s: %v", target, err)
			continue
		}
		go relayConn(conn, target)
	}
}

func relayConn(client net.Conn, target string) {
	defer client.Close()

	upstream, err := net.Dial("tcp", target)
	if err != nil {
		log.Printf("wireguard dial target %s: %v", target, err)
		return
	}
	defer upstream.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(upstream, client)
		if tcpConn, ok := upstream.(*net.TCPConn); ok {
			_ = tcpConn.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(client, upstream)
		if tcpConn, ok := client.(*net.TCPConn); ok {
			_ = tcpConn.CloseWrite()
		}
	}()
	wg.Wait()
}

func decodeWGKey(value string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("expected 32 bytes, got %d", len(key))
	}
	return key, nil
}

func listenPort(addr net.Addr) (uint16, error) {
	switch typed := addr.(type) {
	case *net.UDPAddr:
		return uint16(typed.Port), nil
	default:
		return 0, fmt.Errorf("unexpected listen addr type %T", addr)
	}
}

func normalizeIP(ip net.IP) net.IP {
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	if v16 := ip.To16(); v16 != nil {
		return v16
	}
	return nil
}
