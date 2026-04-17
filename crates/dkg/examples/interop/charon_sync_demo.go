package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	stderrors "errors"
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/obolnetwork/charon/app/version"
	"github.com/obolnetwork/charon/dkg/sync"
	"github.com/obolnetwork/charon/eth2util/enr"
	"github.com/obolnetwork/charon/p2p"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	dataDir := flag.String("data-dir", "", "Directory containing charon-enr-private-key and cluster-lock.json")
	relayURL := flag.String("relay-url", "", "Relay URL, for example http://127.0.0.1:8888")
	flag.Parse()

	if *dataDir == "" || *relayURL == "" {
		flag.Usage()
		os.Exit(2)
	}

	ctx, stopSignal := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignal()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	key, err := p2p.LoadPrivKey(*dataDir)
	if err != nil {
		log.Fatalf("Failed to load private key: %v", err)
	}

	lock, err := loadLock(*dataDir)
	if err != nil {
		log.Fatalf("Failed to load lock: %v", err)
	}

	peerIDs, err := lock.peerIDs()
	if err != nil {
		log.Fatalf("Failed to derive peer IDs: %v", err)
	}

	localPeerID, err := p2p.PeerIDFromKey(key.PubKey())
	if err != nil {
		log.Fatalf("Failed to derive local peer ID: %v", err)
	}

	localNodeNumber, err := localNodeNumber(peerIDs, localPeerID)
	if err != nil {
		log.Fatalf("Failed to derive local node number: %v", err)
	}

	log.Printf("Started charon sync demo local_node=%d local_peer_id=%s data_dir=%s", localNodeNumber, localPeerID, *dataDir)
	printClusterOverview(peerIDs, localPeerID)

	definitionHashHex := hex.EncodeToString(lock.Definition.DefinitionHash)
	relays, err := p2p.NewRelays(ctx, []string{*relayURL}, definitionHashHex)
	if err != nil {
		log.Fatalf("Failed to resolve relays: %v", err)
	}

	connGater, err := p2p.NewConnGater(peerIDs, relays)
	if err != nil {
		log.Fatalf("Failed to build connection gater: %v", err)
	}

	node, err := p2p.NewNode(
		ctx,
		p2p.Config{
			TCPAddrs: []string{"127.0.0.1:0"},
			UDPAddrs: []string{"127.0.0.1:0"},
		},
		key,
		connGater,
		false,
		p2p.NodeTypeQUIC,
	)
	if err != nil {
		log.Fatalf("Failed to create p2p node: %v", err)
	}
	defer node.Close()

	for _, relay := range relays {
		relay := relay
		go p2p.NewRelayReserver(node, relay)(ctx)
	}
	go p2p.NewRelayRouter(node, peerIDs, relays)(ctx)

	hashSig, err := ((*libp2pcrypto.Secp256k1PrivateKey)(key)).Sign(lock.Definition.DefinitionHash)
	if err != nil {
		log.Fatalf("Failed to sign definition hash: %v", err)
	}

	minorVersion := version.Version.Minor()
	server := sync.NewServer(node, len(peerIDs)-1, lock.Definition.DefinitionHash, minorVersion)
	server.Start(ctx)

	var clients []*sync.Client
	for _, peerID := range peerIDs {
		if peerID == localPeerID {
			continue
		}

		client := sync.NewClient(node, peerID, hashSig, minorVersion)
		clients = append(clients, client)

		go func(client *sync.Client, peerID peer.ID) {
			if err := client.Run(ctx); err != nil && !stderrors.Is(err, context.Canceled) {
				log.Printf("Sync failed to peer peer=%s err=%v", p2p.PeerName(peerID), err)
				cancel()
			}
		}(client, peerID)
	}

	if err := waitForClientsConnected(ctx, clients, localNodeNumber, server); err != nil {
		log.Fatalf("Failed while waiting for sync clients: %v", err)
	}

	for _, client := range clients {
		client.DisableReconnect()
	}

	log.Printf("Waiting for peers to connect local_node=%d", localNodeNumber)
	if err := server.AwaitAllConnected(ctx); err != nil {
		log.Fatalf("Failed waiting for all peers connected: %v", err)
	}

	log.Printf("All peers connected local_node=%d", localNodeNumber)

	for step := 1; step <= 2; step++ {
		for _, client := range clients {
			client.SetStep(step)
		}

		log.Printf("Waiting for sync step local_node=%d step=%d", localNodeNumber, step)
		if err := server.AwaitAllAtStep(ctx, step); err != nil {
			log.Fatalf("Failed waiting for step %d: %v", step, err)
		}

		log.Printf("Sync step reached local_node=%d step=%d", localNodeNumber, step)

		if step < 2 {
			select {
			case <-ctx.Done():
				log.Printf("Cancellation received, exiting local_node=%d", localNodeNumber)
				return
			case <-time.After(3 * time.Second):
			}
		}
	}

	log.Printf("Sync demo is now idling until Ctrl+C local_node=%d", localNodeNumber)
	heartbeat := time.NewTicker(5 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Printf("Cancellation received, exiting local_node=%d", localNodeNumber)
			return
		case <-heartbeat.C:
			log.Printf(
				"Sync steady-state heartbeat local_node=%d connected=%d expected=%d",
				localNodeNumber,
				connectedCount(clients),
				len(clients),
			)
		}
	}
}

func loadLock(dataDir string) (lockFile, error) {
	var lock lockFile

	lockBytes, err := os.ReadFile(filepath.Join(dataDir, "cluster-lock.json"))
	if err != nil {
		return lockFile{}, err
	}

	if err := json.Unmarshal(lockBytes, &lock); err != nil {
		return lockFile{}, err
	}

	return lock, nil
}

type lockFile struct {
	Definition lockDefinition `json:"cluster_definition"`
}

type lockDefinition struct {
	DefinitionHash hexBytes       `json:"definition_hash"`
	Operators      []lockOperator `json:"operators"`
}

type lockOperator struct {
	ENR string `json:"enr"`
}

type hexBytes []byte

func (h *hexBytes) UnmarshalJSON(data []byte) error {
	var encoded string
	if err := json.Unmarshal(data, &encoded); err != nil {
		return err
	}

	encoded = strings.TrimPrefix(encoded, "0x")
	decoded, err := hex.DecodeString(encoded)
	if err != nil {
		return err
	}

	*h = decoded
	return nil
}

func (l lockFile) peerIDs() ([]peer.ID, error) {
	peerIDs := make([]peer.ID, 0, len(l.Definition.Operators))
	for _, operator := range l.Definition.Operators {
		record, err := enr.Parse(operator.ENR)
		if err != nil {
			return nil, err
		}

		peerID, err := p2p.PeerIDFromKey(record.PubKey)
		if err != nil {
			return nil, err
		}

		peerIDs = append(peerIDs, peerID)
	}

	return peerIDs, nil
}

func localNodeNumber(peerIDs []peer.ID, localPeerID peer.ID) (int, error) {
	for idx, peerID := range peerIDs {
		if peerID == localPeerID {
			return idx + 1, nil
		}
	}

	return 0, stderrors.New("local peer id is not present in the cluster lock")
}

func printClusterOverview(peerIDs []peer.ID, localPeerID peer.ID) {
	log.Printf("Cluster peer order:")
	for idx, peerID := range peerIDs {
		localMarker := ""
		if peerID == localPeerID {
			localMarker = " (local)"
		}

		log.Printf("Cluster peer peer_index=%d peer_id=%s%s", idx+1, peerID, localMarker)
	}
}

func waitForClientsConnected(
	ctx context.Context,
	clients []*sync.Client,
	localNodeNumber int,
	server *sync.Server,
) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	previousConnected := -1
	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		if err := server.Err(); err != nil {
			return err
		}

		connected := connectedCount(clients)
		if connected != previousConnected {
			log.Printf(
				"Sync client connectivity update local_node=%d connected=%d expected=%d",
				localNodeNumber,
				connected,
				len(clients),
			)
			previousConnected = connected
		}

		if connected == len(clients) {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func connectedCount(clients []*sync.Client) int {
	var connected int
	for _, client := range clients {
		if client.IsConnected() {
			connected++
		}
	}

	return connected
}
