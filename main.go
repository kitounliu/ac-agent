package main

import (
	"bufio"
	crand "crypto/rand"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/CosmWasm/wasmd/x/verifiable-credential/crypto/accumulator"
	"github.com/CosmWasm/wasmd/x/verifiable-credential/crypto/anonymouscredential"

	log "github.com/sirupsen/logrus"

	"github.com/kitounliu/ac-agent/client"

	vctypes "github.com/CosmWasm/wasmd/x/verifiable-credential/types"
)

const SchemaFilePath = "data/schema"

func Run(cc *client.ChainClient) {
loop:
	for {
		log.Println("\nChoose option:\n" +
			"1: Check account balance\n" +
			"2: Create anonymous credential schema (issuer only)\n" +
			"3: Request credential from issuer\n" +
			"4: Issue credentials and update schema on chain (issuer only)\n" +
			"5: Load credential and schema\n" +
			"6: Load schema\n" +
			"7: Request proof\n" +
			"8: Create proof\n" +
			"9: Verify proof\n" +
			"10: Revoke users and update schema on chain (issuer only)\n" +
			"11: Update credential and schema\n" +
			"q: Quit\n")
		reader := bufio.NewReader(os.Stdin)
		// ReadString will block until the delimiter is entered
		input, err := reader.ReadString('\n')
		if err != nil {
			log.Println("An error occurred while reading input. Please try again", err)
			return
		}
		// remove the delimeter from the string
		i := strings.TrimSuffix(input, "\n")
		switch i {
		case "1":
			_, err := cc.GetBalances(cc.Acc.String())
			if err != nil {
				log.Fatalln("An error occurred while querying balance. Please try again", err)
				return
			}
		case "2":
			if cc.Name != "issuer" {
				log.Println("Only issuer can create schema")
				break
			}
			err := cc.NewAnonymousCredentialSchema(4)
			if err != nil {
				log.Fatalln("error creating new ac schema", err)
			}
			res, err := cc.GetVerifiableCredential(cc.SchemaId)
			if err != nil {
				log.Fatalln("error querying anonymous credential schema", err)
			}
			data, err := cc.Ctx.Codec.MarshalJSON(res)
			if err != nil {
				log.Fatalln("error marshalling anonymous credential schema", err)
			}
			log.Infoln("schema query result:", string(data))
		case "3":
			if cc.Name == "issuer" {
				log.Println("error issuer cannot request credential")
				break
			}
			log.Printf("Enter %s's address:\n", cc.Name)
			reader := bufio.NewReader(os.Stdin)
			// ReadString will block until the delimiter is entered
			input, err := reader.ReadString('\n')
			if err != nil {
				log.Fatalln("An error occurred while reading address. Please try again", err)
				return
			}
			// remove the delimeter from the string
			address := strings.TrimSuffix(input, "\n")

			log.Printf("Enter %s's date of birth:\n", cc.Name)
			var dob int
			_, err = fmt.Scanf("%d", &dob)
			if err != nil {
				log.Fatalln("An error occurred while reading date-of-birth. Please try again", err)
				return
			}

			userInfo := client.Info{
				Name:        cc.Name,
				Address:     address,
				DateOfBirth: dob,
			}
			data, err := json.Marshal(userInfo)
			if err != nil {
				log.Fatalln("cannot json marshal user information", err)
			}
			log.Printf("Sending information to issuer: %s\n", string(data))
			requestFilePath := client.DataPath + "/" + cc.Name + ".info"
			err = client.WriteData(requestFilePath, data)
			if err != nil {
				log.Fatalln("Cannot send user information to issuer", err)
			}
		case "4":
			if cc.Name != "issuer" {
				log.Println("Only issuer can issue credential")
				break
			}
			// users to be added
			log.Print("Enter names of users to be added:")
			reader := bufio.NewReader(os.Stdin)
			// ReadString will block until the delimiter is entered
			input, err := reader.ReadString('\n')
			if err != nil {
				log.Fatalln("An error occurred while reading users. Please try again", err)
				return
			}
			names := strings.Split(input, " ")
			for i := range names {
				names[i] = strings.TrimSpace(names[i])
			}

			err = cc.IssueCredentials(names)
			if err != nil {
				log.Fatalln("failed to issue credential", err)
			}
			log.Infoln("user private credentials created")
			// query schema
			res, err := cc.GetVerifiableCredential(cc.SchemaId)
			if err != nil {
				log.Fatalln("error querying anonymous credential schema", err)
			}
			data, err := cc.Ctx.Codec.MarshalJSON(res)
			if err != nil {
				log.Fatalln("error marshalling anonymous credential schema", err)
			}
			log.Infoln("updated schema:", string(data))
		case "5":
			if cc.Name == "issuer" {
				log.Println("Not for issuer")
				break
			}
			credPath := client.KeyPath + "/" + cc.Name + ".cred"
			cred, err := ioutil.ReadFile(credPath)
			if err != nil {
				log.Fatalln("error reading credential")
			}
			log.Println("private credential for ", cc.Name)
			log.Println(string(cred))
			err = json.Unmarshal(cred, &cc.UserCred)
			if err != nil {
				log.Fatalln("error storing credential")
			}

			cc.SchemaId = cc.UserCred.SchemaId

			res, err := cc.GetVerifiableCredential(cc.SchemaId)
			if err != nil {
				log.Fatalln("error querying anonymous credential schema", err)
			}
			vc := res.VerifiableCredential
			err = cc.VerifySchemaWithDid(vc)
			if err != nil {
				log.Infoln("failed to verify schema. Please try another one", err)
				break
			}
			vcSub, ok := res.VerifiableCredential.CredentialSubject.(*vctypes.VerifiableCredential_AnonCredSchema)
			if !ok {
				log.Fatalln("error getting vc subject", err)
			}
			cc.IssuerPp = vcSub.AnonCredSchema.PublicParams
			data, err := cc.Ctx.Codec.MarshalJSON(res)
			if err != nil {
				log.Fatalln("error marshalling anonymous credential schema", err)
			}
			log.Infoln("schema: ", string(data))
		case "6":
			log.Println("Enter schema id:\n")
			reader := bufio.NewReader(os.Stdin)
			// ReadString will block until the delimiter is entered
			input, err := reader.ReadString('\n')
			if err != nil {
				log.Fatalln("An error occurred while reading schema id. Please try again", err)
				return
			}
			// remove the delimeter from the string
			schemaId := strings.TrimSuffix(input, "\n")
			res, err := cc.GetVerifiableCredential(schemaId)
			if err != nil {
				log.Fatalln("error querying anonymous credential schema", err)
			}
			vc := res.VerifiableCredential
			err = cc.VerifySchemaWithDid(vc)
			if err != nil {
				log.Infoln("failed to verify schema. Please try another one", err)
				break
			}

			vcSub, ok := res.VerifiableCredential.CredentialSubject.(*vctypes.VerifiableCredential_AnonCredSchema)
			if !ok {
				log.Fatalln("error getting vc subject", err)
			}
			cc.SchemaId = schemaId
			cc.IssuerPp = vcSub.AnonCredSchema.PublicParams
			log.Infoln("schema loaded successfully")
		case "7":
			var nonce [32]byte
			_, err := crand.Read(nonce[:])
			if err != nil {
				log.Fatalln("error creating random nonce", err)
			}

			req := client.Request{
				Nonce:      nonce[:],
				RevealName: true,
			}
			data, err := json.Marshal(req)
			if err != nil {
				log.Fatalln("error marshalling proof request", err)
			}
			log.Println("proof request:\n", string(data))
			filePath := client.DataPath + "/proof.request"
			err = client.WriteData(filePath, data)
			if err != nil {
				log.Fatalln("error sending request", err)
			}
		case "8":
			// load info
			filePath := client.DataPath + "/" + cc.Name + ".info"
			data, err := ioutil.ReadFile(filePath)
			if err != nil {
				log.Fatalln("error receiving info", err)
			}
			info := client.Info{}
			err = json.Unmarshal(data, &info)
			if err != nil {
				log.Fatalln("error unmarshalling info", err)
			}

			// load request
			filePath = client.DataPath + "/proof.request"
			data, err = ioutil.ReadFile(filePath)
			if err != nil {
				log.Fatalln("error receiving proof request", err)
			}
			req := client.Request{}
			err = json.Unmarshal(data, &req)
			if err != nil {
				log.Fatalln("error unmarshalling proof request", err)
			}

			// create proof
			revealedInfo, proof, err := client.CreateProof(info, req, cc.UserCred, cc.IssuerPp)
			if err != nil {
				log.Fatalln("error creating proof", err)
			}

			proofBytes, err := cc.Ctx.Codec.MarshalJSON(proof)
			if err != nil {
				log.Fatalln("error marshalling proof", err)
			}

			finalProof := client.Proof{
				RevealedInfo: revealedInfo,
				Proof:        proofBytes,
			}
			finalProofBytes, err := json.Marshal(finalProof)
			if err != nil {
				log.Fatalln("error marshalling final proof", err)
			}
			log.Infoln("sending proof:\n", string(finalProofBytes))

			proofPath := client.DataPath + "/proof"
			err = client.WriteData(proofPath, finalProofBytes)
			if err != nil {
				log.Fatalln("error sending proof", err)
			}
		case "9":
			// load proof
			proofPath := client.DataPath + "/proof"
			data, err := ioutil.ReadFile(proofPath)
			if err != nil {
				log.Fatalln("error loading proof", err)
			}
			finalProof := client.Proof{}
			err = json.Unmarshal(data, &finalProof)
			if err != nil {
				log.Fatalln("error unmarshalling final proof", err)
			}

			proof := anonymouscredential.AnonymousCredentialProof{}
			err = cc.Ctx.Codec.UnmarshalJSON(finalProof.Proof, &proof)
			if err != nil {
				log.Fatalln("error unmarshalling proof", err)
			}

			// load request
			requestPath := client.DataPath + "/proof.request"
			data, err = ioutil.ReadFile(requestPath)
			if err != nil {
				log.Fatalln("error receiving proof request", err)
			}
			req := client.Request{}
			err = json.Unmarshal(data, &req)
			if err != nil {
				log.Fatalln("error unmarshalling proof request", err)
			}

			err = client.VerifyProof(finalProof.RevealedInfo, req, &proof, cc.IssuerPp)
			if err != nil {
				log.Info("error verify proof: ", err.Error())
			} else {
				log.Info("proof verified successfully")
			}
		case "10":
			if cc.Name != "issuer" {
				log.Println("Only issuer can revoke credential")
				break
			}
			log.Print("Enter names of users to be revoked:")
			reader := bufio.NewReader(os.Stdin)
			// ReadString will block until the delimiter is entered
			input, err := reader.ReadString('\n')
			if err != nil {
				log.Fatalln("An error occurred while reading address. Please try again", err)
				return
			}
			names := strings.Split(input, " ")
			for i := range names {
				names[i] = strings.TrimSpace(names[i])
			}
			err = cc.RevokeCredentials(names)
			if err != nil {
				log.Fatalln("An error occurred while revoking users. Please try again", err)
				return
			}
			// query schema
			res, err := cc.GetVerifiableCredential(cc.SchemaId)
			if err != nil {
				log.Fatalln("error querying anonymous credential schema", err)
			}
			data, err := cc.Ctx.Codec.MarshalJSON(res)
			if err != nil {
				log.Fatalln("error marshalling anonymous credential schema", err)
			}
			log.Infoln("updated schema:", string(data))
			log.Infoln("successfully revoked users")
		case "11":
			if cc.Name == "issuer" {
				log.Println("Not for issuer")
				break
			}

			if cc.SchemaId == "" {
				log.Println("schema id not set")
				break
			}

			// query new schema
			res, err := cc.GetVerifiableCredential(cc.SchemaId)
			if err != nil {
				log.Fatalln("error querying anonymous credential schema", err)
			}
			vcSub, ok := res.VerifiableCredential.CredentialSubject.(*vctypes.VerifiableCredential_AnonCredSchema)
			if !ok {
				log.Fatalln("error getting vc subject", err)
			}
			oldPP := cc.IssuerPp
			pp := vcSub.AnonCredSchema.PublicParams

			// print schema
			data, err := cc.Ctx.Codec.MarshalJSON(res)
			if err != nil {
				log.Fatalln("error marshalling anonymous credential schema", err)
			}
			log.Infoln("updated schema:", string(data))

			err = client.IsNotRevoked(cc.UserCred.MemberIdSeed, oldPP, pp)
			if err != nil {
				log.Infof("%s is reovked and cannot update witness", cc.Name)
				cc.IssuerPp = pp
				log.Infoln("updated schema")
				break
			}

			newWit, err := accumulator.UpdateWitness(oldPP.AccumulatorPublicParams, pp.AccumulatorPublicParams, cc.UserCred.MemberWitness)
			if err != nil {
				log.Fatalln("failed to update private credential (mebership witness):", err.Error())
			}
			cc.UserCred.MemberWitness = newWit
			cc.IssuerPp = pp
			log.Infoln("successfully updated witness and schema")
		case "q":
			fmt.Println("Exit program")
			break loop
		default:
			fmt.Println("No such option")
		}
	}

}

func main() {
	fmt.Print("Enter new user name: ")
	reader := bufio.NewReader(os.Stdin)
	// ReadString will block until the delimiter is entered
	name, _ := reader.ReadString('\n')
	name = strings.TrimSpace(name)
	password := "insecure password for " + name
	clientCtx := client.InitClient(name, password)

	Run(clientCtx)

}
