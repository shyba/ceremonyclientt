package data

import (
	"bytes"
	"time"

	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/tries"
)

func (
	e *DataClockConsensusEngine,
) GetFrameProverTries() []*tries.RollingFrecencyCritbitTrie {
	e.frameProverTriesMx.RLock()
	frameProverTries := make(
		[]*tries.RollingFrecencyCritbitTrie,
		len(e.frameProverTries),
	)

	for i, trie := range e.frameProverTries {
		newTrie := &tries.RollingFrecencyCritbitTrie{}
		b, err := trie.Serialize()
		if err != nil {
			panic(err)
		}

		err = newTrie.Deserialize(b)
		if err != nil {
			panic(err)
		}
		frameProverTries[i] = newTrie
	}

	e.frameProverTriesMx.RUnlock()
	return frameProverTries
}

func (e *DataClockConsensusEngine) runLoop() {
	dataFrameCh := e.dataTimeReel.NewFrameCh()
	for e.GetState() < consensus.EngineStateStopping {
		peerCount := e.pubSub.GetNetworkPeersCount()
		if peerCount < e.minimumPeersRequired {
			e.logger.Info(
				"waiting for minimum peers",
				zap.Int("peer_count", peerCount),
			)
			time.Sleep(1 * time.Second)
		} else {
			latestFrame, err := e.dataTimeReel.Head()
			if err != nil {
				panic(err)
			}

			select {
			case dataFrame := <-dataFrameCh:
				latestFrame = e.processFrame(latestFrame, dataFrame)
			case <-time.After(20 * time.Second):
				dataFrame, err := e.dataTimeReel.Head()
				if err != nil {
					panic(err)
				}

				latestFrame = e.processFrame(latestFrame, dataFrame)
			}
		}
	}
}

func (e *DataClockConsensusEngine) processFrame(
	latestFrame *protobufs.ClockFrame,
	dataFrame *protobufs.ClockFrame,
) *protobufs.ClockFrame {
	e.logger.Info(
		"current frame head",
		zap.Uint64("frame_number", dataFrame.FrameNumber),
	)
	var err error
	if !e.GetFrameProverTries()[0].Contains(e.provingKeyBytes) {
		if latestFrame, err = e.collect(dataFrame); err != nil {
			e.logger.Error("could not collect", zap.Error(err))
		}
	}

	if latestFrame != nil &&
		dataFrame.FrameNumber > latestFrame.FrameNumber {
		latestFrame = dataFrame
	}

	if e.latestFrameReceived < latestFrame.FrameNumber {
		e.latestFrameReceived = latestFrame.FrameNumber
	}
	e.frameProverTriesMx.Lock()
	e.frameProverTries = e.dataTimeReel.GetFrameProverTries()
	e.frameProverTriesMx.Unlock()

	trie := e.GetFrameProverTries()[0]
	selBI, _ := dataFrame.GetSelector()
	sel := make([]byte, 32)
	sel = selBI.FillBytes(sel)

	if bytes.Equal(
		trie.FindNearest(sel).External.Key,
		e.provingKeyAddress,
	) {
		var nextFrame *protobufs.ClockFrame
		if nextFrame, err = e.prove(dataFrame); err != nil {
			e.logger.Error("could not prove", zap.Error(err))
			e.stateMx.Lock()
			if e.state < consensus.EngineStateStopping {
				e.state = consensus.EngineStateCollecting
			}
			e.stateMx.Unlock()
			return dataFrame
		}

		e.dataTimeReel.Insert(nextFrame, true)

		if err = e.publishProof(nextFrame); err != nil {
			e.logger.Error("could not publish", zap.Error(err))
			e.stateMx.Lock()
			if e.state < consensus.EngineStateStopping {
				e.state = consensus.EngineStateCollecting
			}
			e.stateMx.Unlock()
		}

		return nextFrame
	} else {
		if !e.IsInProverTrie(e.pubSub.GetPeerID()) &&
			dataFrame.Timestamp > time.Now().UnixMilli()-30000 {
			e.logger.Info("announcing prover join")
			e.announceProverJoin()
		}
		return latestFrame
	}
}
