package client

import (
	"bytes"
	"fmt"

	accumcrypto "github.com/coinbase/kryptology/pkg/accumulator"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/fetchai/fetchd/x/verifiable-credential/crypto"
	"github.com/fetchai/fetchd/x/verifiable-credential/crypto/accumulator"
	"github.com/fetchai/fetchd/x/verifiable-credential/crypto/anonymouscredential"
	"github.com/fetchai/fetchd/x/verifiable-credential/crypto/bbsplus"

	"github.com/coinbase/kryptology/pkg/signatures/common"
)

func CreateProof(info Info, request Request, credential *PrivateCredential, pp *anonymouscredential.PublicParameters) (map[int]interface{}, *anonymouscredential.AnonymousCredentialProof, error) {
	// create proof messages
	msg0 := bbsplus.Curve.Scalar.Hash([]byte(credential.MemberIdSeed))
	msg1 := bbsplus.Curve.Scalar.Hash([]byte(info.Name))
	msg2 := bbsplus.Curve.Scalar.Hash([]byte(info.Address))
	msg3 := bbsplus.Curve.Scalar.New(info.DateOfBirth)
	//	msgs := []curves.Scalar{msg10, msg11, msg12, msg13}

	eb, err := new(accumcrypto.ExternalBlinding).New(accumulator.Curve)
	if err != nil {
		return nil, nil, err
	}

	proofMsgs := []common.ProofMessage{
		&common.SharedBlindingMessage{
			Message:  msg0,
			Blinding: eb.GetBlinding(),
		},
	}

	revealedInfo := map[int]interface{}{}
	if request.RevealName {
		proofMsgs = append(proofMsgs, &common.RevealedMessage{Message: msg1})
		revealedInfo[1] = info.Name
	} else {
		proofMsgs = append(proofMsgs, &common.ProofSpecificMessage{Message: msg1})
	}

	if request.RevealAddress {
		proofMsgs = append(proofMsgs, &common.RevealedMessage{Message: msg2})
		revealedInfo[2] = info.Address
	} else {
		proofMsgs = append(proofMsgs, &common.ProofSpecificMessage{Message: msg2})
	}

	if request.RevealDateOfBirth {
		proofMsgs = append(proofMsgs, &common.RevealedMessage{Message: msg3})
		revealedInfo[3] = info.DateOfBirth
	} else {
		proofMsgs = append(proofMsgs, &common.ProofSpecificMessage{Message: msg3})
	}

	// create bbs+ proof
	pok, bbsOkm, err := bbsplus.CreateProofPre(pp.BbsPlusPublicParams, credential.BbsSig, request.Nonce, proofMsgs)
	if err != nil {
		return nil, nil, err
	}
	// create membership proof
	mpc, accumOkm, memProofEntropy, err := accumulator.CreateMembershipProofPre(pp.AccumulatorPublicParams, credential.MemberWitness, eb)
	// merge okm to create challenge
	challengeOkm := crypto.CombineChanllengeOkm(bbsOkm, accumOkm)
	// complete bbs+ proof
	bbsProof, err := bbsplus.CreateProofPost(pok, challengeOkm)
	// complete membership proof
	memProof, err := accumulator.CreateMembershipProofPost(mpc, challengeOkm)

	// the final proof is
	proof := anonymouscredential.AnonymousCredentialProof{
		Nonce:              request.Nonce,
		Challenge:          challengeOkm,
		BbsPlusProof:       bbsProof,
		AccumulatorEntropy: memProofEntropy,
		AccumulatorProof:   memProof,
	}

	// for testing
	err = VerifyProof(revealedInfo, request, &proof, pp)
	if err != nil {
		fmt.Println("crypto.go: line 83: verification after proof creation failed")
	} else {
		fmt.Println("crypto.go: line 85: verification after proof creation successful")
	}

	return revealedInfo, &proof, nil
}

func VerifyProof(revealedInfo map[int]interface{}, request Request, proof *anonymouscredential.AnonymousCredentialProof, pp *anonymouscredential.PublicParameters) error {
	revealedMsgs := map[int]curves.Scalar{}

	if request.RevealName {
		revealedMsgs[1] = bbsplus.Curve.Scalar.Hash([]byte(revealedInfo[1].(string)))
	}
	if request.RevealAddress {
		revealedMsgs[2] = bbsplus.Curve.Scalar.Hash([]byte(revealedInfo[2].(string)))
	}
	if request.RevealDateOfBirth {
		revealedMsgs[3] = bbsplus.Curve.Scalar.New(revealedInfo[3].(int))
	}

	if !bytes.Equal(request.Nonce, proof.Nonce) {
		return fmt.Errorf("nonce does not match expect %s got %s", request.Nonce, proof.Nonce)
	}

	okm, err := anonymouscredential.VerifyProof(pp, revealedMsgs, proof)
	if err != nil {
		return err
	}
	err = crypto.IsChallengeEqual(proof.Challenge, okm)

	return err
}

func IsNotRevoked(memberIdSeed string, oldPp *anonymouscredential.PublicParameters, pp *anonymouscredential.PublicParameters) error {
	n1 := len(oldPp.AccumulatorPublicParams.States)
	n2 := len(pp.AccumulatorPublicParams.States)
	if n1 >= n2 {
		return fmt.Errorf("no update for accumulator states")
	}

	memberId := bbsplus.Curve.Scalar.Hash([]byte(memberIdSeed))

	for i := n1; i < n2; i++ {
		dels := new(accumcrypto.ElementSet)
		err := dels.UnmarshalBinary(pp.AccumulatorPublicParams.States[i].Update.Deletions)
		if err != nil {
			return err
		}

		for _, d := range dels.Elements {
			if d.Cmp(memberId) == 0 {
				return fmt.Errorf("member revoked")
			}
		}
	}

	return nil
}
