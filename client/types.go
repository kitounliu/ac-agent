package client

import (
	"github.com/cosmos/cosmos-sdk/client"
	sdk "github.com/cosmos/cosmos-sdk/types"
	didTypes "github.com/fetchai/fetchd/x/did/types"
	"github.com/fetchai/fetchd/x/verifiable-credential/crypto/anonymouscredential"
)

const ValidatorName = "validator"
const ValidatorPassPath = "keys/validator.passcode"
const ValidatorKeyPath = "keys/validator.armor"

const DataPath = "data"
const KeyPath = "keys"

const NodeURI = "http://127.0.0.1:26657"
const ChainID = "localnet"
const HomeDir = "data"

type ChainClient struct {
	Ctx      client.Context
	Name     string
	Acc      sdk.AccAddress
	Did      didTypes.DID
	SchemaId string
	IssuerSk *anonymouscredential.PrivateKey
	IssuerPp *anonymouscredential.PublicParameters
	UserCred *PrivateCredential
}

type Info struct {
	Name        string `json:"name"`
	Address     string `json:"address"`
	DateOfBirth int    `json:"date-of-birth"`
}

type Request struct {
	Nonce             []byte `json:"nonce"`
	RevealName        bool   `json:"reveal-name"`
	RevealAddress     bool   `json:"reveal-address"`
	RevealDateOfBirth bool   `json:"reveal-date-of-birth"`
}

type PrivateCredential struct {
	SchemaId      string `json:"schema-id"`
	MemberIdSeed  string `json:"member-id-seed"`
	BbsSig        []byte `json:"bbs-sig"`
	MemberWitness []byte `json:"member-witness"`
}

type Proof struct {
	RevealedInfo map[int]interface{} `json:"revealed-info"`
	Proof        []byte              `json:"proof"`
}
