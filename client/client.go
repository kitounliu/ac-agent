package client

import (
	"encoding/json"
	"fmt"
	"time"

	accumcrypto "github.com/coinbase/kryptology/pkg/accumulator"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/fetchai/fetchd/x/verifiable-credential/crypto/accumulator"
	"github.com/fetchai/fetchd/x/verifiable-credential/crypto/anonymouscredential"
	"github.com/fetchai/fetchd/x/verifiable-credential/crypto/bbsplus"
	"github.com/fetchai/fetchd/x/verifiable-credential/types"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/client/tx"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/crypto/hd"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authTypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/fetchai/fetchd/app"
	didtypes "github.com/fetchai/fetchd/x/did/types"
	vctypes "github.com/fetchai/fetchd/x/verifiable-credential/types"

	"io/ioutil"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
)

// for transferring balance for new users
func loadValidator(kr keyring.Keyring) keyring.Keyring {
	passcode := "password"
	armor, err := ioutil.ReadFile(ValidatorKeyPath)
	if err != nil {
		log.Fatalln("error reading validator keys", err)
	}
	err = kr.ImportPrivKey(ValidatorName, string(armor), passcode)
	if err != nil {
		log.Fatalln("error loading private key", err)
	}
	return kr
}

func InitClient(name string, password string) *ChainClient {
	//	cfg := sdk.GetConfig()
	//	cfg.SetBech32PrefixForAccount(app.Bech32PrefixAccAddr, app.Bech32PrefixAccPub)
	//	cfg.Seal()
	app.SetConfig()

	encodingConfig := app.MakeEncodingConfig()

	kr := keyring.NewInMemory(encodingConfig.Codec)
	// load validator to give some balance to new user
	kr = loadValidator(kr)
	// create keys for new user
	_, mnemonic, err := kr.NewMnemonic(name, keyring.English, sdk.GetConfig().GetFullBIP44Path(), "", hd.Secp256k1)
	if err != nil {
		log.Fatalln("error creating new key", err)
	}
	log.WithFields(log.Fields{
		"mnemonic": mnemonic,
	}).Infoln("created new key for", name)
	// now get the account
	user, err := kr.Key(name)
	if err != nil {
		log.Fatalln("cannot load stored key by uid", err)
	}
	pk, err := user.GetPubKey()
	if err != nil {
		log.Fatalln("cannot get public-key", err)
	}
	// print public key
	apk, err := codectypes.NewAnyWithValue(pk)
	if err != nil {
		log.Fatalln("cannot convert public-key", err)
	}
	bz, err := codec.ProtoMarshalJSON(apk, nil)
	if err != nil {
		log.Fatalln("cannot marshal public-key", err)
	}
	log.Infoln("public-key is: ", string(bz))
	userAddr, err := user.GetAddress()
	if err != nil {
		log.Fatalln("cannot get user address", err)
	}
	log.Infoln("address is: ", userAddr.String())

	kv, err := kr.Key(ValidatorName)
	if err != nil {
		log.Fatalln("cannot find validator key", err)
	}

	// RPC client for transactions
	netCli, err := client.NewClientFromNode(NodeURI)
	if err != nil {
		log.Fatalln("error connecting to the node", err)
	}

	kvAddr, err := kv.GetAddress()
	if err != nil {
		log.Fatalln("failed to get validator address", err)
	}
	initClientCtx := client.Context{}.
		WithCodec(encodingConfig.Codec).
		WithInterfaceRegistry(encodingConfig.InterfaceRegistry).
		WithTxConfig(encodingConfig.TxConfig).
		WithAccountRetriever(authTypes.AccountRetriever{}).
		WithBroadcastMode(flags.BroadcastBlock).
		WithChainID(ChainID).
		WithKeyring(kr).
		WithHomeDir(fmt.Sprintf("%s/%s/", HomeDir, name)).
		WithNodeURI(NodeURI).
		WithFromName(ValidatorName).
		WithFromAddress(kvAddr).
		WithSkipConfirmation(true).
		WithClient(netCli)
	//WithLegacyAmino(encodingConfig.Amino).
	//WithInput(os.Stdin).

	cc := ChainClient{
		Ctx:  initClientCtx,
		Name: name,
		Acc:  userAddr,
	}

	// give new user some balance
	coins, err := sdk.ParseCoinsNormalized("10000000afet")
	if err != nil {
		log.Fatalln("cannot creat coins", err)
	}
	// send some coins from validator to the new user
	log.Printf("giving %s some funds\n", cc.Name)
	msg := banktypes.NewMsgSend(kvAddr, userAddr, coins)
	pf := pflag.NewFlagSet("default", pflag.PanicOnError)
	if err := tx.GenerateOrBroadcastTxCLI(cc.Ctx, pf, msg); err != nil {
		log.Fatalln("failed tx for initial payment", err)
	}

	// set client to the new user
	clientCtx := cc.Ctx.WithFromName(name).WithFromAddress(userAddr)
	cc.Ctx = clientCtx

	// create a did for the new user
	log.Printf("creating a new did for %s", cc.Name)
	didID := uuid.New().String()
	did := didtypes.NewChainDID(ChainID, didID)
	cc.Did = did
	ki, err := cc.Ctx.Keyring.Key(cc.Name)
	if err != nil {
		log.Fatalln("cannot load stored key by uid", err)
	}
	log.Print(cc.Did.String())
	msgDid := initDIDDoc(cc.Did, ki)
	if err := tx.GenerateOrBroadcastTxCLI(cc.Ctx, pf, msgDid); err != nil {
		log.Fatalln("failed tx for creating did: ", err)
	}

	log.Println("querying did")
	res, err := cc.GetDid(did.String())
	if err != nil {
		log.Fatalln("failed to query uid", err)
	}

	// write did to file
	data, err := cc.Ctx.Codec.MarshalJSON(res)
	if err != nil {
		log.Fatalln("error marshalling did response", err)
	}
	log.Println(string(data))
	filePath := DataPath + "/" + cc.Name + ".did"
	err = WriteData(filePath, data)
	if err != nil {
		log.Fatalln("error writing did response", err)
	}

	// write pubkey to file
	data, err = cc.Ctx.Codec.MarshalInterfaceJSON(pk)
	if err != nil {
		log.Fatalln("error marshalling did response", err)
	}
	pkPath := DataPath + "/" + cc.Name + ".pk"
	err = WriteData(pkPath, data)
	if err != nil {
		log.Fatalln("error writing public key", err)
	}

	return &cc
}

func initDIDDoc(did didtypes.DID, ki *keyring.Record) sdk.Msg {
	// verification method id
	kiAddr, err := ki.GetAddress()
	if err != nil {
		log.Fatalln("error getting address", err)
	}
	kiPk, err := ki.GetPubKey()
	if err != nil {
		log.Fatalln("error getting public key", err)
	}
	vmID := did.NewVerificationMethodID(kiAddr.String())
	verification := didtypes.NewVerification(
		didtypes.NewVerificationMethod(
			vmID,
			did,
			didtypes.NewPublicKeyMultibase(kiPk.Bytes(), didtypes.DIDVMethodTypeEcdsaSecp256k1VerificationKey2019),
		),
		[]string{didtypes.Authentication},
		nil,
	)

	return didtypes.NewMsgCreateDidDocument(
		did.String(),
		didtypes.Verifications{verification},
		didtypes.Services{},
		kiAddr.String(),
	)
}

func (cc *ChainClient) NewAnonymousCredentialSchema(msgLen int) error {
	sk, pp, err := anonymouscredential.NewAnonymousCredentialSchema(msgLen)
	if err != nil {
		return err
	}
	cc.IssuerSk = sk
	cc.IssuerPp = pp

	subType := []string{"BBS+", "Accumulator"}
	subContext := []string{
		"https://eprint.iacr.org/2016/663.pdf",
		"https://eprint.iacr.org/2020/777.pdf",
		"https://github.com/coinbase/kryptology",
		"https://github.com/kitounliu/kryptology/tree/combine",
	}
	anonySub := types.NewAnonymousCredentialSchemaSubject(
		cc.Did.String(),
		subType,
		subContext,
		pp,
	)

	now := time.Now()
	id := uuid.New().String()
	vcId := types.NewChainVcId(cc.Ctx.ChainID, id)
	vc := types.NewAnonymousCredentialSchema(
		vcId,
		cc.Did.String(),
		now,
		anonySub,
	)

	cc.SchemaId = vcId
	log.Println("anonymous credential schema id:", vcId)

	vmID := cc.Did.NewVerificationMethodID(cc.Acc.String())
	signedVc, err := vc.Sign(cc.Ctx.Keyring, cc.Acc, vmID)
	if err != nil {
		return err
	}

	msg := types.NewMsgIssueAnonymousCredentialSchema(
		signedVc,
		cc.Acc.String(),
	)

	pf := pflag.NewFlagSet("default", pflag.PanicOnError)
	return tx.GenerateOrBroadcastTxCLI(cc.Ctx, pf, msg)
}

func (cc *ChainClient) IssueCredentials(names []string) error {
	sk := cc.IssuerSk
	pp := cc.IssuerPp

	// users to be added: load user requests
	var userInfo []Info
	for _, name := range names {
		requestPath := DataPath + "/" + name + ".info"
		rq, err := ioutil.ReadFile(requestPath)
		if err != nil {
			return err
		}
		info := Info{}
		err = json.Unmarshal(rq, &info)
		if err != nil {
			return err
		}
		userInfo = append(userInfo, info)
	}
	var seeds []string
	var sigs [][]byte
	// create bbs+ signature; 0-th message is reserved for membership id
	for _, info := range userInfo {
		memberSeed := uuid.New().String()
		seeds = append(seeds, memberSeed)

		msg10 := bbsplus.Curve.Scalar.Hash([]byte(memberSeed))
		msg11 := bbsplus.Curve.Scalar.Hash([]byte(info.Name))
		msg12 := bbsplus.Curve.Scalar.Hash([]byte(info.Address))
		msg13 := bbsplus.Curve.Scalar.New(info.DateOfBirth)
		msgs := []curves.Scalar{msg10, msg11, msg12, msg13}

		bbsSig, err := sk.BbsPlusKey.Sign(pp.BbsPlusPublicParams, msgs)
		if err != nil {
			return err
		}
		sigs = append(sigs, bbsSig)
	}

	// initialise accumulator
	var members []accumcrypto.Element
	for _, seed := range seeds {
		mem := accumulator.Curve.Scalar.Hash([]byte(seed))
		members = append(members, mem)
	}
	adds := accumcrypto.ElementSet{Elements: members}
	dels := accumcrypto.ElementSet{}

	_, state, err := pp.AccumulatorPublicParams.UpdateAccumulatorState(sk.AccumulatorKey, adds, dels)
	if err != nil {
		return err
	}

	// create witness for each member
	var wits [][]byte
	for _, mem := range members {
		wit, err := sk.AccumulatorKey.InitMemberWitness(pp.AccumulatorPublicParams, mem)
		if err != nil {
			return err
		}
		wits = append(wits, wit)
	}

	// send private credentials to users
	for i, name := range names {
		sc := PrivateCredential{
			cc.SchemaId,
			seeds[i],
			sigs[i],
			wits[i],
		}
		scBytes, err := json.Marshal(sc)
		if err != nil {
			return err
		}

		userPath := KeyPath + "/" + name + ".cred"
		err = WriteData(userPath, scBytes)
		if err != nil {
			return err
		}
	}

	// update schema onchain
	res, err := cc.GetVerifiableCredential(cc.SchemaId)
	if err != nil {
		log.Fatalln("error querying anonymous credential schema", err)
	}
	vc := res.VerifiableCredential
	now := time.Now()
	vc.IssuanceDate = &now
	vc, err = vc.UpdateAccumulatorState(state)
	if err != nil {
		log.Fatalf("error updating accumulator state")
	}

	vc.Proof = nil
	vmID := cc.Did.NewVerificationMethodID(cc.Acc.String())
	signedVc, err := vc.Sign(cc.Ctx.Keyring, cc.Acc, vmID)

	// generate and broadcast transaction
	msg := types.NewMsgUpdateAccumulatorState(signedVc.Id, signedVc.IssuanceDate, state, signedVc.Proof, cc.Acc.String())
	pf := pflag.NewFlagSet("default", pflag.PanicOnError)

	return tx.GenerateOrBroadcastTxCLI(cc.Ctx, pf, msg)
}

func (cc *ChainClient) RevokeCredentials(names []string) error {
	sk := cc.IssuerSk
	pp := cc.IssuerPp

	// load users' private credentials
	var seeds []string
	for _, name := range names {
		sc := PrivateCredential{}
		userPath := KeyPath + "/" + name + ".cred"
		data, err := ioutil.ReadFile(userPath)
		if err != nil {
			return err
		}
		err = json.Unmarshal(data, &sc)
		if err != nil {
			return err
		}
		seeds = append(seeds, sc.MemberIdSeed)
	}

	var members []accumcrypto.Element
	for _, seed := range seeds {
		mem := accumulator.Curve.Scalar.Hash([]byte(seed))
		members = append(members, mem)
	}
	adds := accumcrypto.ElementSet{}
	dels := accumcrypto.ElementSet{Elements: members}

	_, state, err := pp.AccumulatorPublicParams.UpdateAccumulatorState(sk.AccumulatorKey, adds, dels)
	if err != nil {
		return err
	}

	// update schema onchain
	res, err := cc.GetVerifiableCredential(cc.SchemaId)
	if err != nil {
		log.Fatalln("error querying anonymous credential schema", err)
	}
	vc := res.VerifiableCredential
	now := time.Now()
	vc.IssuanceDate = &now
	vc, err = vc.UpdateAccumulatorState(state)
	if err != nil {
		log.Fatalf("error updating accumulator state")
	}

	vc.Proof = nil
	vmID := cc.Did.NewVerificationMethodID(cc.Acc.String())
	signedVc, err := vc.Sign(cc.Ctx.Keyring, cc.Acc, vmID)

	// generate and broadcast transaction
	msg := types.NewMsgUpdateAccumulatorState(signedVc.Id, signedVc.IssuanceDate, state, signedVc.Proof, cc.Acc.String())
	pf := pflag.NewFlagSet("default", pflag.PanicOnError)

	return tx.GenerateOrBroadcastTxCLI(cc.Ctx, pf, msg)
}

// offchain verification of schema using a given did
func (cc *ChainClient) VerifySchemaWithDid(vc vctypes.VerifiableCredential) error {
	// issuer.did is the root of trust
	didPath := DataPath + "/issuer.did"
	data, err := ioutil.ReadFile(didPath)
	if err != nil {
		log.Fatalln("error reading issuer did", err)
	}
	res := didtypes.QueryDidDocumentResponse{}
	err = cc.Ctx.Codec.UnmarshalJSON(data, &res)
	if err != nil {
		return err
	}
	doc := res.DidDocument

	if vc.Issuer != doc.Id {
		return fmt.Errorf("vc issuer does not match did: expect %s got %s", doc.Id, vc.Issuer)
	}

	// from ValidateProof in wasmd/x/verifiable-credential/keeper/verifiable-credential.go
	if vc.Proof == nil {
		return fmt.Errorf("proof is empty")
	}
	//check relationships
	authorized := false
	verificationRelationships := []string{didtypes.Authentication, didtypes.AssertionMethod}
	methodRelationships := doc.GetVerificationRelationships(vc.Proof.VerificationMethod)
Outer:
	for _, gotR := range methodRelationships {
		for _, wantR := range verificationRelationships {
			if gotR == wantR {
				authorized = true
				break Outer
			}
		}
	}

	if !authorized {
		return fmt.Errorf("not authorised")
	}

	pk, err := doc.GetVerificationMethodPublicKey(vc.Proof.GetVerificationMethod())
	if err != nil {
		return fmt.Errorf("failed to get public key from did %s", doc.Id)
	}

	return vc.Validate(pk)
}
