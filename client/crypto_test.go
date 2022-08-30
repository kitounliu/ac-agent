package client

import (
	"encoding/json"
	"fmt"
	"testing"

	accumcrypto "github.com/coinbase/kryptology/pkg/accumulator"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/fetchai/fetchd/x/verifiable-credential/crypto/accumulator"
	"github.com/fetchai/fetchd/x/verifiable-credential/crypto/anonymouscredential"
	"github.com/fetchai/fetchd/x/verifiable-credential/crypto/bbsplus"
	"github.com/stretchr/testify/require"
)

func TestProofVerification(t *testing.T) {
	sk, pp, err := anonymouscredential.NewAnonymousCredentialSchema(4)
	require.NoError(t, err)

	fmt.Println("pp =", *pp)
	// create bbs+ credential for alice
	aliceMemberIdSeed := []byte("a member id for alice")
	msg10 := bbsplus.Curve.Scalar.Hash(aliceMemberIdSeed)
	msg11 := bbsplus.Curve.Scalar.Hash([]byte("alice"))
	msg12 := bbsplus.Curve.Scalar.Hash([]byte("london"))
	msg13 := bbsplus.Curve.Scalar.New(19990101)
	msgs1 := []curves.Scalar{msg10, msg11, msg12, msg13}
	aliceBbsSig, err := sk.BbsPlusKey.Sign(pp.BbsPlusPublicParams, msgs1)
	require.NoError(t, err)

	// create bbs+ credential for bob
	bobMemberIdseed := []byte("a member id for bob")
	msg20 := bbsplus.Curve.Scalar.Hash(bobMemberIdseed)
	msg21 := bbsplus.Curve.Scalar.Hash([]byte("bob"))
	msg22 := bbsplus.Curve.Scalar.Hash([]byte("cambridge"))
	msg23 := bbsplus.Curve.Scalar.New(20010101)
	msgs2 := []curves.Scalar{msg20, msg21, msg22, msg23}
	bobBbsSig, err := sk.BbsPlusKey.Sign(pp.BbsPlusPublicParams, msgs2)
	_ = bobBbsSig // no more error
	require.NoError(t, err)

	// initialise accumulator with alice and bob
	mem1 := accumulator.Curve.Scalar.Hash(aliceMemberIdSeed)
	mem2 := accumulator.Curve.Scalar.Hash(bobMemberIdseed)
	adds := accumcrypto.ElementSet{Elements: []accumcrypto.Element{mem1, mem2}}
	dels := accumcrypto.ElementSet{}
	pp.AccumulatorPublicParams, _, err = pp.AccumulatorPublicParams.UpdateAccumulatorState(sk.AccumulatorKey, adds, dels)
	require.NoError(t, err)

	fmt.Println("pp =", *pp)
	// create witness for each member
	alice_wit, err := sk.AccumulatorKey.InitMemberWitness(pp.AccumulatorPublicParams, mem1)
	require.NoError(t, err)
	bob_wit, err := sk.AccumulatorKey.InitMemberWitness(pp.AccumulatorPublicParams, mem2)
	_ = bob_wit // no more error
	require.NoError(t, err)

	aliceCred := PrivateCredential{
		MemberIdSeed:  "a member id for alice",
		BbsSig:        aliceBbsSig,
		MemberWitness: alice_wit,
		SchemaId:      "placeholder",
	}

	info := Info{
		"alice",
		"london",
		19990101,
	}

	request := Request{
		[]byte("a nonce"),
		true,
		false,
		false,
	}

	revealedInfo, proof, err := CreateProof(info, request, &aliceCred, pp)
	require.NoError(t, err)

	err = VerifyProof(revealedInfo, request, proof, pp)
	require.NoError(t, err)

	fmt.Println("crypto_test.go: line 83: before marshal credential ", aliceCred.MemberIdSeed)
	d, err := json.Marshal(aliceCred)
	require.NoError(t, err)

	fmt.Println("crypto_test.go: line 86: marshalled credential ", string(d))
	ac := PrivateCredential{}
	err = json.Unmarshal(d, &ac)
	require.NoError(t, err)
	require.Equal(t, ac.MemberIdSeed, aliceCred.MemberIdSeed)
	require.Equal(t, ac.BbsSig, aliceCred.BbsSig)
	require.Equal(t, ac.MemberWitness, aliceCred.MemberWitness)
}
