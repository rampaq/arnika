package wg

import (
	"encoding/base64"
	"fmt"
	"log"
	"math"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// VPN represents encrypted network interface (wireguard)
type VPN interface {
	// SetKey sets pre-shared encryption key
	SetKey(key string) error
	// Deactivates peer commication; (Wireguard might take up-to two minutes)
	DeactivatePeer() error
	// Get interface public key (our pubkey)
	GetPublicKey() (string, error)
}

// WireGuardHandler provides an interface to the WireGuard client.
type WireGuardHandler struct {
	// conn is the WireGuard client connection.
	conn *wgctrl.Client
	// wg interface name
	ifname string
	// peer's public key
	peerPubKey wgtypes.Key
	// is interface activated?
	active bool
	// mutex for activating/deactivating interface
	mu sync.Mutex
	// expiration timer
	timer *time.Timer
	timerDur time.Duration
}

// Setup Wireguard interface - initiate handler and set random PSK for wg iface.
//
// Parameters:
// - ifname: wireguard interface name, see Warning
// - peerPublicKey: peer's public key (b64 encoded).
//
// First, it sets random PSK to prevent further VPN communication until proper PSK is set.
// Second, make sure the interface is deactivated. The PSK might not be set by WG right away.
// When SetKey is called, the interface is automatically brought up.
//
// Warning:
// The WG interface should be already fully configured (via `wg setconf` & `ip address add`).
// It is STRONGLY preferred that the interface is in "down" state so that no data is transferred with degraded security in between creation of the activated interface and running arnika.
//
// Returns:
// - a pointer to a WireGuardHandler.
// - error: an error if the setup failed.
func SetupWireGuardIF(ifname string, peerPublicKey string) (*WireGuardHandler, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	publicKey, err := wgtypes.ParseKey(peerPublicKey)
	if err != nil {
		return nil, err
	}
	wgh := WireGuardHandler{conn: client, ifname: ifname, peerPubKey: publicKey, active: true}

	err = wgh.interfaceDown()
	if err != nil {
		return nil, fmt.Errorf("failed to deactivate interface during setup: %w", err)
	}
	err = wgh.setRandomKey()
	if err != nil {
		return nil, fmt.Errorf("failed to set random PSK during setup: %w", err)
	}
	log.Printf("set random key for peer\n")
	return &wgh, nil
}

func (wg *WireGuardHandler) GetPublicKey() (string, error) {
	dev, err := wg.conn.Device(wg.ifname)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(dev.PublicKey[:]), nil

}

// AddExpirationTimer adds an timer which deactivates peer when SetKey is not called during duration dur.
// The created timer is inactive upon calling AddExpirationTimer.
//
// When duration is zero duration, no timer is created.
//
// Returns whether new timer was created.
func (wg *WireGuardHandler) AddExpirationTimer(dur time.Duration) bool {
	if dur == 0 {
		return false
	}
	wg.timerDur = dur
	wg.timer = time.AfterFunc(math.MaxInt64, func() {
		err := wg.DeactivatePeer()
		if err != nil {
			log.Printf("Error in ExpirationTimer function: %v\n", err)
			return
		}
		log.Printf("No PSK set during %s, peer disabled\n", dur)
	})
	wg.timer.Stop()
	return true
}

// SetKey sets the preshared key for a WireGuard device.
//
// It automatically activates the wg interface after setting the PSK. If AddExpirationTimer was called earlier, activate the timer.
//
// Parameters:
// - pskString is the preshared key as a b64 string.
//
// Returns:
// - error: an error if any occurred during the process.
func (wg *WireGuardHandler) SetKey(pskString string) error {
	psk, err := wgtypes.ParseKey(pskString)
	if err != nil {
		return err
	}
	err = wg.setRawKey(psk)
	if err != nil {
		return fmt.Errorf("failed to set key: %w", err)
	}
	err = wg.interfaceUp()
	if err != nil {
		return fmt.Errorf("failed to activate interface: %w", err)
	}
	if wg.timer != nil {
		wg.timer.Reset(wg.timerDur)
	}
	return err
}

// DeactivatePeer disables peer communication by first setting random PSK and if that fails, brings the whole wg interface down.
// Note that propagating the PSK, and hence deactivating the peer, can take upto 2 minutes. That is inherent to the Wireguard rekeying mechanism. The 2 minute timer can be overcomed by deactivating&activating the interface to trigger rekeying.
//
// No parameters.
//
// Returns:
// - error: an error if any occurred during the process.
func (wg *WireGuardHandler) DeactivatePeer() error {
	err := wg.setRandomKey()
	if err != nil {
		// failsafe
		log.Printf("Failed to set random PSK, deactivating %s\n", wg.ifname)
		err = wg.interfaceDown()
		if err != nil {
			return fmt.Errorf("failed to set random PSK & failed to deactivate interface: %w", err)
		}
	}

	// when peer is deactivated, no need to run timer
	if wg.timer != nil {
		wg.timer.Stop()
	}
	return nil
}

func (wg *WireGuardHandler) setRawKey(psk wgtypes.Key) error {
	devices, err := wg.conn.Devices()
	if err != nil {
		return err
	}
	if len(devices) != 1 {
		return fmt.Errorf("expected 1 wireguard device, found %d", len(devices))
	}
	peer := wgtypes.PeerConfig{
		PublicKey:    wg.peerPubKey,
		UpdateOnly:   true,
		PresharedKey: &psk,
	}
	return wg.conn.ConfigureDevice(wg.ifname, wgtypes.Config{Peers: []wgtypes.PeerConfig{peer}})
}

func (wg *WireGuardHandler) setRandomKey() error {
	key, err := wgtypes.GenerateKey()
	if err != nil {
		return err
	}
	return wg.setRawKey(key)
}

func (wg *WireGuardHandler) interfaceDown() error {
	wg.mu.Lock()
	defer wg.mu.Unlock()

	if !wg.active {
		return nil
	}

	link, err := netlink.LinkByName(wg.ifname)
	if err != nil {
		return fmt.Errorf("failed to find interface %s: %w", wg.ifname, err)
	}
	err = netlink.LinkSetDown(link)
	if err != nil {
		return fmt.Errorf("failed to bring interface down: %w", err)
	}

	wg.active = false
	return nil
}

func (wg *WireGuardHandler) interfaceUp() error {
	wg.mu.Lock()
	defer wg.mu.Unlock()

	if wg.active {
		return nil
	}

	link, err := netlink.LinkByName(wg.ifname)
	if err != nil {
		return fmt.Errorf("failed to find interface %s: %w", wg.ifname, err)
	}
	err = netlink.LinkSetUp(link)
	if err != nil {
		return fmt.Errorf("failed to bring interface up: %w", err)
	}

	wg.active = true
	return nil
}
