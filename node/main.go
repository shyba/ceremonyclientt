//go:build !js && !wasm

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"math/big"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	rdebug "runtime/debug"
	"runtime/pprof"
	"strconv"
	"strings"
	"syscall"
	"time"

	"go.uber.org/zap"
	"golang.org/x/crypto/sha3"
	"google.golang.org/protobuf/proto"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
	"source.quilibrium.com/quilibrium/monorepo/node/utils"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/pbnjay/memory"
	"github.com/pkg/errors"
	"source.quilibrium.com/quilibrium/monorepo/node/app"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/node/crypto"
	"source.quilibrium.com/quilibrium/monorepo/node/crypto/kzg"
	"source.quilibrium.com/quilibrium/monorepo/node/rpc"
)

var (
	configDirectory = flag.String(
		"config",
		filepath.Join(".", ".config"),
		"the configuration directory",
	)
	balance = flag.Bool(
		"balance",
		false,
		"print the node's confirmed token balance to stdout and exit",
	)
	dbConsole = flag.Bool(
		"db-console",
		false,
		"starts the node in database console mode",
	)
	importPrivKey = flag.String(
		"import-priv-key",
		"",
		"creates a new config using a specific key from the phase one ceremony",
	)
	peerId = flag.Bool(
		"peer-id",
		false,
		"print the peer id to stdout from the config and exit",
	)
	cpuprofile = flag.String(
		"cpuprofile",
		"",
		"write cpu profile to file",
	)
	memprofile = flag.String(
		"memprofile",
		"",
		"write memory profile after 20m to this file",
	)
	nodeInfo = flag.Bool(
		"node-info",
		false,
		"print node related information",
	)
	debug = flag.Bool(
		"debug",
		false,
		"sets log output to debug (verbose)",
	)
	dhtOnly = flag.Bool(
		"dht-only",
		false,
		"sets a node to run strictly as a dht bootstrap peer (not full node)",
	)
	network = flag.Uint(
		"network",
		0,
		"sets the active network for the node (mainnet = 0, primary testnet = 1)",
	)
	signatureCheck = flag.Bool(
		"signature-check",
		signatureCheckDefault(),
		"enables or disables signature validation (default true or value of QUILIBRIUM_SIGNATURE_CHECK env var)",
	)
	core = flag.Int(
		"core",
		0,
		"specifies the core of the process (defaults to zero, the initial launcher)",
	)
	parentProcess = flag.Int(
		"parent-process",
		0,
		"specifies the parent process pid for a data worker",
	)
	integrityCheck = flag.Bool(
		"integrity-check",
		false,
		"runs an integrity check on the store, helpful for confirming backups are not corrupted (defaults to false)",
	)
	emergencyRepair = flag.Bool(
		"emergency-repair",
		false,
		"performs an attempt at emergency repair. extremely dangerous, take a backup of your store before running.",
	)
)

func signatureCheckDefault() bool {
	envVarValue, envVarExists := os.LookupEnv("QUILIBRIUM_SIGNATURE_CHECK")
	if envVarExists {
		def, err := strconv.ParseBool(envVarValue)
		if err == nil {
			return def
		} else {
			fmt.Println("Invalid environment variable QUILIBRIUM_SIGNATURE_CHECK, must be 'true' or 'false'. Got: " + envVarValue)
		}
	}

	return true
}

func main() {
	flag.Parse()

	if *signatureCheck {
		if runtime.GOOS == "windows" {
			fmt.Println("Signature check not available for windows yet, skipping...")
		} else {
			ex, err := os.Executable()
			if err != nil {
				panic(err)
			}

			b, err := os.ReadFile(ex)
			if err != nil {
				fmt.Println(
					"Error encountered during signature check – are you running this " +
						"from source? (use --signature-check=false)",
				)
				panic(err)
			}

			checksum := sha3.Sum256(b)
			digest, err := os.ReadFile(ex + ".dgst")
			if err != nil {
				fmt.Println("Digest file not found")
				os.Exit(1)
			}

			parts := strings.Split(string(digest), " ")
			if len(parts) != 2 {
				fmt.Println("Invalid digest file format")
				os.Exit(1)
			}

			digestBytes, err := hex.DecodeString(parts[1][:64])
			if err != nil {
				fmt.Println("Invalid digest file format")
				os.Exit(1)
			}

			if !bytes.Equal(checksum[:], digestBytes) {
				fmt.Println("Invalid digest for node")
				os.Exit(1)
			}

			count := 0

			for i := 1; i <= len(config.Signatories); i++ {
				signatureFile := fmt.Sprintf(ex+".dgst.sig.%d", i)
				sig, err := os.ReadFile(signatureFile)
				if err != nil {
					continue
				}

				pubkey, _ := hex.DecodeString(config.Signatories[i-1])
				if !ed448.Verify(pubkey, digest, sig, "") {
					fmt.Printf("Failed signature check for signatory #%d\n", i)
					os.Exit(1)
				}
				count++
			}

			if count < ((len(config.Signatories)-4)/2)+((len(config.Signatories)-4)%2) {
				fmt.Printf("Quorum on signatures not met")
				os.Exit(1)
			}

			fmt.Println("Signature check passed")
		}
	} else {
		fmt.Println("Signature check disabled, skipping...")
	}

	if *memprofile != "" && *core == 0 {
		go func() {
			for {
				time.Sleep(5 * time.Minute)
				f, err := os.Create(*memprofile)
				if err != nil {
					log.Fatal(err)
				}
				pprof.WriteHeapProfile(f)
				f.Close()
			}
		}()
	}

	if *cpuprofile != "" && *core == 0 {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	if *balance {
		config, err := config.LoadConfig(*configDirectory, "", false)
		if err != nil {
			panic(err)
		}

		printBalance(config)

		return
	}

	if *peerId {
		config, err := config.LoadConfig(*configDirectory, "", false)
		if err != nil {
			panic(err)
		}

		printPeerID(config.P2P)
		return
	}

	if *importPrivKey != "" {
		config, err := config.LoadConfig(*configDirectory, *importPrivKey, false)
		if err != nil {
			panic(err)
		}

		printPeerID(config.P2P)
		fmt.Println("Import completed, you are ready for the launch.")
		return
	}

	if *nodeInfo {
		config, err := config.LoadConfig(*configDirectory, "", false)
		if err != nil {
			panic(err)
		}

		printNodeInfo(config)
		return
	}

	if !*dbConsole && *core == 0 {
		config.PrintLogo()
		config.PrintVersion(uint8(*network))
		fmt.Println(" ")
	}

	nodeConfig, err := config.LoadConfig(*configDirectory, "", false)
	if err != nil {
		panic(err)
	}

	if *emergencyRepair {
		fmt.Println("Emergency Repair Mode")
		fmt.Println("WARNING")
		fmt.Println("WARNING")
		fmt.Println("WARNING")
		fmt.Println(
			"This operation will try an attempt at repairing your 1.4.21.1 store. " +
				"It is not guaranteed to work, and may make things worse. Before you " +
				"run this, please take a backup of your store. Proofs generated by " +
				"this repair tool will evaluate at single core, and earn less QUIL " +
				"for the proofs produced than you would have previously earned with a " +
				"valid backup. Do you wish to proceed?",
		)
		fmt.Println("WARNING")
		fmt.Println("WARNING")
		fmt.Println("WARNING")

		fmt.Printf("Proceed? (Y/N): ")

		var response string
		_, err := fmt.Scanln(&response)
		if err != nil {
			fmt.Println("Invalid response, exiting without running repair.")
			os.Exit(1)
		}

		response = strings.ToUpper(strings.TrimSpace(response))
		if response == "Y" || response == "YES" {
			runEmergencyRepair(nodeConfig)
		} else {
			fmt.Println(
				"Did not receive confirmation, exiting without running repair.",
			)
			os.Exit(0)
		}
	}

	if *network != 0 {
		if nodeConfig.P2P.BootstrapPeers[0] == config.BootstrapPeers[0] {
			fmt.Println(
				"Node has specified to run outside of mainnet but is still " +
					"using default bootstrap list. This will fail. Exiting.",
			)
			os.Exit(1)
		}

		nodeConfig.Engine.GenesisSeed = fmt.Sprintf(
			"%02x%s",
			byte(*network),
			nodeConfig.Engine.GenesisSeed,
		)
		nodeConfig.P2P.Network = uint8(*network)
		fmt.Println(
			"Node is operating outside of mainnet – be sure you intended to do this.",
		)
	}

	clearIfTestData(*configDirectory, nodeConfig)

	if *dbConsole {
		console, err := app.NewDBConsole(nodeConfig)
		if err != nil {
			panic(err)
		}

		console.Run()
		return
	}

	if *dhtOnly {
		done := make(chan os.Signal, 1)
		signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)
		dht, err := app.NewDHTNode(nodeConfig)
		if err != nil {
			panic(err)
		}

		go func() {
			dht.Start()
		}()

		<-done
		dht.Stop()
		return
	}

	if *core != 0 {
		// runtime.GOMAXPROCS(2)
		rdebug.SetGCPercent(9999)

		if nodeConfig.Engine.DataWorkerMemoryLimit == 0 {
			nodeConfig.Engine.DataWorkerMemoryLimit = 1792 * 1024 * 1024 // 1.75GiB
		}

		rdebug.SetMemoryLimit(nodeConfig.Engine.DataWorkerMemoryLimit)

		if nodeConfig.Engine.DataWorkerBaseListenMultiaddr == "" {
			nodeConfig.Engine.DataWorkerBaseListenMultiaddr = "/ip4/127.0.0.1/tcp/%d"
		}

		if nodeConfig.Engine.DataWorkerBaseListenPort == 0 {
			nodeConfig.Engine.DataWorkerBaseListenPort = 40000
		}

		if *parentProcess == 0 && len(nodeConfig.Engine.DataWorkerMultiaddrs) == 0 {
			panic("parent process pid not specified")
		}

		l, err := zap.NewProduction()
		if err != nil {
			panic(err)
		}

		rpcMultiaddr := fmt.Sprintf(
			nodeConfig.Engine.DataWorkerBaseListenMultiaddr,
			int(nodeConfig.Engine.DataWorkerBaseListenPort)+*core-1,
		)

		if len(nodeConfig.Engine.DataWorkerMultiaddrs) != 0 {
			rpcMultiaddr = nodeConfig.Engine.DataWorkerMultiaddrs[*core-1]
		}

		srv, err := rpc.NewDataWorkerIPCServer(
			rpcMultiaddr,
			l,
			uint32(*core)-1,
			qcrypto.NewWesolowskiFrameProver(l),
			nodeConfig,
			*parentProcess,
		)
		if err != nil {
			panic(err)
		}

		err = srv.Start()
		if err != nil {
			panic(err)
		}
		return
	}

	fmt.Println("Loading ceremony state and starting node...")

	if !*integrityCheck {
		go spawnDataWorkers(nodeConfig)
	}

	kzg.Init()

	report := RunSelfTestIfNeeded(*configDirectory, nodeConfig)

	if *core == 0 {
		for {
			genesis, err := config.DownloadAndVerifyGenesis(*network)
			if err != nil {
				time.Sleep(10 * time.Minute)
				continue
			}

			nodeConfig.Engine.GenesisSeed = genesis.GenesisSeedHex
			break
		}
	}

	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)
	var node *app.Node
	if *debug {
		node, err = app.NewDebugNode(nodeConfig, report)
	} else {
		node, err = app.NewNode(nodeConfig, report)
	}

	if err != nil {
		panic(err)
	}

	if *integrityCheck {
		fmt.Println("Running integrity check...")
		node.VerifyProofIntegrity()
		fmt.Println("Integrity check passed!")
		return
	}

	// runtime.GOMAXPROCS(1)

	if nodeConfig.ListenGRPCMultiaddr != "" {
		srv, err := rpc.NewRPCServer(
			nodeConfig.ListenGRPCMultiaddr,
			nodeConfig.ListenRestMultiaddr,
			node.GetLogger(),
			node.GetDataProofStore(),
			node.GetClockStore(),
			node.GetCoinStore(),
			node.GetKeyManager(),
			node.GetPubSub(),
			node.GetMasterClock(),
			node.GetExecutionEngines(),
		)
		if err != nil {
			panic(err)
		}

		go func() {
			err := srv.Start()
			if err != nil {
				panic(err)
			}
		}()
	}

	node.Start()

	<-done
	stopDataWorkers()
	node.Stop()
}

func runEmergencyRepair(cfg *config.Config) {
	fmt.Println("Starting emergency repair.")
	kzg.Init()
	fmt.Println(
		"Opening pebble database. If you see a invalid chunk error, your " +
			"database is corrupted beyond the abilities of this tool to repair.",
	)

	db := store.NewPebbleDB(cfg.DB)
	defer db.Close()
	fmt.Println("Scanning for gaps in record...")

	logger, err := zap.NewDevelopment()
	if err != nil {
		panic(err)
	}

	pstore := store.NewPebbleDataProofStore(db, logger)
	peerId := getPeerID(cfg.P2P)

	increment, _, _, err := pstore.GetLatestDataTimeProof([]byte(peerId))
	if err != nil {
		fmt.Println(
			"Could not find latest proof. Please ensure you are using the correct " +
				"config.yml and the path to the store in the config is correct. (Hint: " +
				"try an absolute path for the store)",
		)
		os.Exit(1)
	}

	fmt.Println(
		"Latest proof found, increment:", increment, " – iterating to find gaps...",
	)

	gapStarts := []uint32{}

	for i := uint32(0); i < increment; i++ {
		fmt.Println("Checking increment", i)
		_, _, _, _, err := pstore.GetDataTimeProof(
			[]byte(peerId),
			uint32(i),
		)

		if err != nil {
			if !errors.Is(err, store.ErrNotFound) {
				fmt.Println("Uncorrectable error detected: ", err)
				os.Exit(1)
			}

			fmt.Println("Missing record at increment", i, " – adding to repair set")
			gapStarts = append(gapStarts, i-1)
		}
	}

	if len(gapStarts) == 0 {
		fmt.Println("No gaps found, quitting.")
		os.Exit(0)
	}

	kprover := qcrypto.NewKZGInclusionProver(logger)
	wprover := qcrypto.NewWesolowskiFrameProver(logger)

	for _, gapPredecessor := range gapStarts {
		prevIndex := -1
		hashes := []byte{}
		previousCommitment := []byte{}
		proofs := [][]byte{}
		commitment := []byte{}
		_, _, _, previousOutput, err := pstore.GetDataTimeProof(
			[]byte(peerId),
			gapPredecessor,
		)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) && len(gapStarts) > 1 &&
				gapPredecessor == uint32(0xFFFFFFFF) {
				fmt.Println(
					"Could not load predecessor data time proof, store is severely "+
						"corrupted. Please review the logs above. If you encounter this "+
						"scenario starting from increment 0 -",
					gapStarts[len(gapStarts)-1],
					"create a new 1.4.21.1 store, keeping this config.yml and "+
						"keys.yml, and run the node up to",
					gapStarts[len(gapStarts)-1],
				)
			}
			fmt.Println("Uncorrectable error detected: ", err)
			os.Exit(1)
		}
		_, _, previousCommitment, _ = app.GetOutputs(previousOutput)

		fmt.Println(
			"Missing record at increment", gapPredecessor+1, "– repairing...",
		)

		input := []byte{}
		input = append(input, []byte(peerId)...)
		input = append(input, previousCommitment...)
		proof, _ := wprover.RecalculatePreDuskChallengeProof(
			input,
			0,
			gapPredecessor+1,
		)
		proofs = append(proofs, proof)

		hashes, commitment, prevIndex = performDataCommitment(
			kprover,
			proofs,
			1,
			uint64(128),
		)

		p, err := kprover.ProveRaw(
			hashes,
			0,
			uint64(128),
		)
		if err != nil {
			fmt.Println("Error while proving", err, "– stopping")
			os.Exit(1)
		}

		output := serializeOutput(
			uint32(prevIndex),
			proofs,
			commitment,
			p,
		)

		txn, err := pstore.NewTransaction()
		if err != nil {
			fmt.Println("Error while preparing transaction", err, "– stopping")
			os.Exit(1)
		}

		fmt.Println("Storing repaired proof, increment:", gapPredecessor+1)
		err = pstore.PutDataTimeProof(
			txn,
			1,
			[]byte(peerId),
			gapPredecessor+1,
			previousCommitment,
			output,
			true,
		)
		if err != nil {
			fmt.Println("Error while saving proof", err, "– stopping")
			os.Exit(1)
		}

		if err := txn.Commit(); err != nil {
			fmt.Println("Error while committing transaction", err, "– stopping")
			os.Exit(1)
		}
	}

	fmt.Println("Emergency repair completed successfully.")
	os.Exit(0)
}

func serializeOutput(
	previousIndex uint32,
	previousOutputs [][]byte,
	kzgCommitment []byte,
	kzgProof []byte,
) []byte {
	serializedOutput := []byte{}
	serializedOutput = binary.BigEndian.AppendUint32(
		serializedOutput,
		previousIndex,
	)
	serializedOutput = append(serializedOutput, previousOutputs[previousIndex]...)
	serializedOutput = append(serializedOutput, kzgCommitment...)
	serializedOutput = append(serializedOutput, kzgProof...)
	return serializedOutput
}

func performDataCommitment(
	kprover *qcrypto.KZGInclusionProver,
	proofs [][]byte,
	parallelism int,
	polySize uint64,
) ([]byte, []byte, int) {
	// Take the VDF outputs and generate some deterministic outputs to feed
	// into a KZG commitment:
	output := []byte{}
	for i := 0; i < len(proofs); i++ {
		h := sha3.Sum512(proofs[i])
		output = append(output, h[:]...)
	}
	nextInput, err := kprover.CommitRaw(output, polySize)
	if err != nil {
		panic(err)
	}
	inputHash := sha3.Sum256(nextInput)
	inputHashBI := big.NewInt(0).SetBytes(inputHash[:])
	prevIndex := int(inputHashBI.Mod(
		inputHashBI,
		big.NewInt(int64(parallelism)),
	).Int64())
	return output, nextInput, prevIndex
}

var dataWorkers []*exec.Cmd

func spawnDataWorkers(nodeConfig *config.Config) {
	if len(nodeConfig.Engine.DataWorkerMultiaddrs) != 0 {
		fmt.Println(
			"Data workers configured by multiaddr, be sure these are running...",
		)
		return
	}

	process, err := os.Executable()
	if err != nil {
		panic(err)
	}

	cores := runtime.GOMAXPROCS(0)
	dataWorkers = make([]*exec.Cmd, cores-1)
	fmt.Printf("Spawning %d data workers...\n", cores-1)

	for i := 1; i <= cores-1; i++ {
		i := i
		go func() {
			for {
				args := []string{
					fmt.Sprintf("--core=%d", i),
					fmt.Sprintf("--parent-process=%d", os.Getpid()),
				}
				args = append(args, os.Args[1:]...)
				cmd := exec.Command(process, args...)
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stdout
				err := cmd.Start()
				if err != nil {
					panic(err)
				}

				dataWorkers[i-1] = cmd
				cmd.Wait()
				time.Sleep(25 * time.Millisecond)
				fmt.Printf("Data worker %d stopped, restarting...\n", i)
			}
		}()
	}
}

func stopDataWorkers() {
	for i := 0; i < len(dataWorkers); i++ {
		err := dataWorkers[i].Process.Signal(os.Kill)
		if err != nil {
			fmt.Printf(
				"fatal: unable to kill worker with pid %d, please kill this process!\n",
				dataWorkers[i].Process.Pid,
			)
		}
	}
}

func RunSelfTestIfNeeded(
	configDir string,
	nodeConfig *config.Config,
) *protobufs.SelfTestReport {
	logger, _ := zap.NewProduction()

	cores := runtime.GOMAXPROCS(0)
	if len(nodeConfig.Engine.DataWorkerMultiaddrs) != 0 {
		cores = len(nodeConfig.Engine.DataWorkerMultiaddrs) + 1
	}

	memory := memory.TotalMemory()
	d, err := os.Stat(filepath.Join(configDir, "store"))
	if d == nil {
		err := os.Mkdir(filepath.Join(configDir, "store"), 0755)
		if err != nil {
			panic(err)
		}
	}

	report := &protobufs.SelfTestReport{}

	report.Cores = uint32(cores)
	report.Memory = binary.BigEndian.AppendUint64([]byte{}, memory)
	disk := utils.GetDiskSpace(nodeConfig.DB.Path)
	report.Storage = binary.BigEndian.AppendUint64([]byte{}, disk)
	logger.Info("writing report")

	report.Capabilities = []*protobufs.Capability{
		{
			ProtocolIdentifier: 0x020000,
		},
	}
	reportBytes, err := proto.Marshal(report)
	if err != nil {
		panic(err)
	}

	err = os.WriteFile(
		filepath.Join(configDir, "SELF_TEST"),
		reportBytes,
		fs.FileMode(0600),
	)
	if err != nil {
		panic(err)
	}

	return report
}

func clearIfTestData(configDir string, nodeConfig *config.Config) {
	_, err := os.Stat(filepath.Join(configDir, "RELEASE_VERSION"))
	if os.IsNotExist(err) {
		fmt.Println("Clearing test data...")
		err := os.RemoveAll(nodeConfig.DB.Path)
		if err != nil {
			panic(err)
		}

		versionFile, err := os.OpenFile(
			filepath.Join(configDir, "RELEASE_VERSION"),
			os.O_CREATE|os.O_RDWR,
			fs.FileMode(0600),
		)
		if err != nil {
			panic(err)
		}

		_, err = versionFile.Write([]byte{0x01, 0x00, 0x00})
		if err != nil {
			panic(err)
		}

		err = versionFile.Close()
		if err != nil {
			panic(err)
		}
	}
}

func printBalance(config *config.Config) {
	if config.ListenGRPCMultiaddr == "" {
		_, _ = fmt.Fprintf(os.Stderr, "gRPC Not Enabled, Please Configure\n")
		os.Exit(1)
	}

	conn, err := app.ConnectToNode(config)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	client := protobufs.NewNodeServiceClient(conn)

	balance, err := app.FetchTokenBalance(client)
	if err != nil {
		panic(err)
	}

	conversionFactor, _ := new(big.Int).SetString("1DCD65000", 16)
	r := new(big.Rat).SetFrac(balance.Owned, conversionFactor)
	fmt.Println("Owned balance:", r.FloatString(12), "QUIL")
	fmt.Println("Note: bridged balance is not reflected here, you must bridge back to QUIL to use QUIL on mainnet.")
}

func getPeerID(p2pConfig *config.P2PConfig) peer.ID {
	peerPrivKey, err := hex.DecodeString(p2pConfig.PeerPrivKey)
	if err != nil {
		panic(errors.Wrap(err, "error unmarshaling peerkey"))
	}

	privKey, err := crypto.UnmarshalEd448PrivateKey(peerPrivKey)
	if err != nil {
		panic(errors.Wrap(err, "error unmarshaling peerkey"))
	}

	pub := privKey.GetPublic()
	id, err := peer.IDFromPublicKey(pub)
	if err != nil {
		panic(errors.Wrap(err, "error getting peer id"))
	}

	return id
}

func printPeerID(p2pConfig *config.P2PConfig) {
	id := getPeerID(p2pConfig)

	fmt.Println("Peer ID: " + id.String())
}

func printNodeInfo(cfg *config.Config) {
	if cfg.ListenGRPCMultiaddr == "" {
		_, _ = fmt.Fprintf(os.Stderr, "gRPC Not Enabled, Please Configure\n")
		os.Exit(1)
	}

	printPeerID(cfg.P2P)

	conn, err := app.ConnectToNode(cfg)
	if err != nil {
		fmt.Println("Could not connect to node. If it is still booting, please wait.")
		os.Exit(1)
	}
	defer conn.Close()

	client := protobufs.NewNodeServiceClient(conn)

	nodeInfo, err := app.FetchNodeInfo(client)
	if err != nil {
		panic(err)
	}

	fmt.Println("Version: " + config.FormatVersion(nodeInfo.Version))
	fmt.Println("Max Frame: " + strconv.FormatUint(nodeInfo.GetMaxFrame(), 10))
	fmt.Println("Peer Score: " + strconv.FormatUint(nodeInfo.GetPeerScore(), 10))
	printBalance(cfg)
}
