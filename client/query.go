package client

import (
	"context"

	didtypes "github.com/CosmWasm/wasmd/x/did/types"
	vctypes "github.com/CosmWasm/wasmd/x/verifiable-credential/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	log "github.com/sirupsen/logrus"
)

// GetBalances retrieves all the balances for an account
func (cc *ChainClient) GetBalances(address string) (sdk.Coins, error) {
	bankClient := banktypes.NewQueryClient(cc.Ctx)
	bankRes, err := bankClient.AllBalances(
		context.Background(),
		&banktypes.QueryAllBalancesRequest{Address: address},
	)
	if err != nil {
		log.Errorln("error requesting balance", err)
		return sdk.NewCoins(), err
	}
	log.Infoln("balances for", address, "are", bankRes.GetBalances())
	return bankRes.GetBalances(), nil
}

func (cc *ChainClient) GetDid(didId string) (*didtypes.QueryDidDocumentResponse, error) {
	qc := didtypes.NewQueryClient(cc.Ctx)
	res, err := qc.DidDocument(
		context.Background(),
		&didtypes.QueryDidDocumentRequest{
			didId,
		})

	return res, err
}

func (cc *ChainClient) GetVerifiableCredential(vcId string) (*vctypes.QueryVerifiableCredentialResponse, error) {
	qc := vctypes.NewQueryClient(cc.Ctx)
	res, err := qc.VerifiableCredential(
		context.Background(),
		&vctypes.QueryVerifiableCredentialRequest{
			vcId,
		})
	return res, err
}
