package application

import (
	"github.com/pkg/errors"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

func (a *TokenApplication) handleAnnounce(
	currentFrameNumber uint64,
	lockMap map[string]struct{},
	t *protobufs.AnnounceProverRequest,
) (
	[]*protobufs.TokenOutput,
	error,
) {
	var primary *protobufs.Ed448Signature
	payload := []byte{}

	if t == nil || t.PublicKeySignaturesEd448 == nil ||
		len(t.PublicKeySignaturesEd448) == 0 {
		return nil, errors.Wrap(ErrInvalidStateTransition, "handle announce")
	}
	for i, p := range t.PublicKeySignaturesEd448 {
		if _, touched := lockMap[string(p.PublicKey.KeyValue)]; touched {
			return nil, errors.Wrap(ErrInvalidStateTransition, "handle announce")
		}

		if p.PublicKey == nil || p.Signature == nil ||
			p.PublicKey.KeyValue == nil {
			return nil, errors.Wrap(ErrInvalidStateTransition, "handle announce")
		}
		if i == 0 {
			primary = p
		} else {
			payload = append(payload, p.PublicKey.KeyValue...)
			if err := p.Verify(primary.PublicKey.KeyValue); err != nil {
				return nil, errors.Wrap(ErrInvalidStateTransition, "handle announce")
			}
		}
	}
	if primary == nil {
		return nil, errors.Wrap(ErrInvalidStateTransition, "handle announce")
	}
	if err := primary.Verify(payload); err != nil {
		return nil, errors.Wrap(ErrInvalidStateTransition, "handle announce")
	}

	for _, p := range t.PublicKeySignaturesEd448[1:] {
		lockMap[string(p.PublicKey.KeyValue)] = struct{}{}
	}

	outputs := []*protobufs.TokenOutput{}
	if currentFrameNumber >= PROOF_FRAME_CUTOFF {
		outputs = append(outputs, &protobufs.TokenOutput{
			Output: &protobufs.TokenOutput_Announce{
				Announce: t,
			},
		})
	}

	return outputs, nil
}
