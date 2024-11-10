package application

import (
	"encoding/binary"

	"github.com/pkg/errors"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

func (a *TokenApplication) handleDataAnnounceProverPause(
	currentFrameNumber uint64,
	lockMap map[string]struct{},
	t *protobufs.AnnounceProverPause,
) (
	[]*protobufs.TokenOutput,
	error,
) {
	if currentFrameNumber < PROOF_FRAME_CUTOFF {
		return nil, errors.Wrap(ErrInvalidStateTransition, "handle pause")
	}

	payload := []byte("pause")

	if t == nil || t.PublicKeySignatureEd448 == nil {
		return nil, errors.Wrap(ErrInvalidStateTransition, "handle pause")
	}

	if t.PublicKeySignatureEd448.PublicKey == nil ||
		t.PublicKeySignatureEd448.Signature == nil ||
		t.PublicKeySignatureEd448.PublicKey.KeyValue == nil ||
		t.Filter == nil || len(t.Filter) != 32 ||
		t.FrameNumber > currentFrameNumber {
		return nil, errors.Wrap(ErrInvalidStateTransition, "handle pause")
	}
	if _, touched := lockMap[string(
		t.PublicKeySignatureEd448.PublicKey.KeyValue,
	)]; touched {
		return nil, errors.Wrap(ErrInvalidStateTransition, "handle pause")
	}

	payload = binary.BigEndian.AppendUint64(payload, t.FrameNumber)
	payload = append(payload, t.Filter...)

	if err := t.PublicKeySignatureEd448.Verify(payload); err != nil {
		return nil, errors.Wrap(ErrInvalidStateTransition, "handle pause")
	}

	address, err := a.getAddressFromSignature(t.PublicKeySignatureEd448)
	if err != nil {
		return nil, errors.Wrap(err, "handle pause")
	}

	inTries := false
	for _, t := range a.Tries {
		inTries = inTries || t.Contains(address)
	}

	lockMap[string(t.PublicKeySignatureEd448.PublicKey.KeyValue)] = struct{}{}
	if !inTries {
		return nil, errors.Wrap(errors.New("in prover trie"), "handle pause")
	}
	return []*protobufs.TokenOutput{
		&protobufs.TokenOutput{
			Output: &protobufs.TokenOutput_Pause{
				Pause: t,
			},
		},
	}, nil
}
