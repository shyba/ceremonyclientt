package protobufs

import (
	"encoding/binary"

	"github.com/iden3/go-iden3-crypto/poseidon"
	pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/pkg/errors"
)

func (t *TokenRequest) Priority() uint64 {
	switch p := t.Request.(type) {
	case *TokenRequest_Mint:
		if len(p.Mint.Proofs) >= 3 {
			return binary.BigEndian.Uint64(p.Mint.Proofs[2])
		}
	}
	return 0
}

func (t *MintCoinRequest) RingAndParallelism(
	ringCalc func(addr []byte) int,
) (int, uint32, error) {
	payload := []byte("mint")
	for _, p := range t.Proofs {
		payload = append(payload, p...)
	}
	if err := t.Signature.Verify(payload); err != nil {
		return -1, 0, errors.New("invalid")
	}

	pk, err := pcrypto.UnmarshalEd448PublicKey(
		t.Signature.PublicKey.KeyValue,
	)
	if err != nil {
		return -1, 0, errors.New("invalid")
	}

	peerId, err := peer.IDFromPublicKey(pk)
	if err != nil {
		return -1, 0, errors.New("invalid")
	}

	altAddr, err := poseidon.HashBytes([]byte(peerId))
	if err != nil {
		return -1, 0, errors.New("invalid")
	}

	ring := ringCalc(altAddr.FillBytes(make([]byte, 32)))
	if ring == -1 {
		return -1, 0, errors.New("invalid")
	}

	if t.Proofs != nil && len(t.Proofs) >= 3 && len(t.Proofs[1]) == 4 {
		return ring, binary.BigEndian.Uint32(t.Proofs[1]), nil
	}

	return -1, 0, errors.New("invalid")
}
