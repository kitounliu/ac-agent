# Self-sovereign identity (SSI)
## KYC demo for anonymous credential




### Running demo with local WasmD node
Install wasmd
```
git clone https://github.com/kitounliu/wasmd.git
cd wasmd
git checkout ssi
make install

```



Setup WasmD node
```s
# Initialise test chain

# Clean state 
rm -rf ~/.wasm*

# default home is ~/.wasmd
# initialize wasmd configuration files
wasmd init localnet --chain-id localnet

# create validator address

wasmd keys add validator 
# copy the validator passcode to file "ac-agent/keys/validator.passcode"

wasmd keys export validator
# input the passcode to export validator private key and copy it to "ac-agent/keys/validator.armor"

wasmd add-genesis-account $(wasmd keys show validator -a) 100000000000000000000000stake

wasmd gentx validator 10000000000000000000000stake --chain-id localnet

# collect gentxs to genesis
wasmd collect-gentxs 

# validate the genesis file
wasmd validate-genesis 

# Enable rest-api
sed -i '/^\[api\]$/,/^\[/ s/^enable = false/enable = true/' ~/.wasmd/config/app.toml

# run the node
wasmd start
```


To run demo
```s
git clone https://github.com/kitounliu/ac-agent.git
cd ac-agent

# start Alice
go run main.go
# input name "alice"

# start Bob in an another terminal
go run main.go
# input name "bob"

# start Issuer in an another terminal
go run main.go
# input name "issuer". Note, Alice and Bob's names can be changed, but issuer must be called "issuer"
```


Main workflow
```
1. Issuer creates a verifiable credential for anonymous credential schema: choose option 2
2. Alice requests credential from issuer: choose option 3 and input Alice's address (e.g., london) and date of birth (e.g., 19990101)
3. Bob requests credential from issuer similar as above
4. Issuer creates private credentials for Alice and Bob: choose option 4 and input names (e.g., alice bob)
5. Alice loads private credential and schema: choose option 5
6. Bob loads private credential and schema: choose option 5
7. Bob requests a proof from Alice: choose option 7. Assume Bob wants Alice to disclose her name but not address or date of birth
8. Alice creates a proof using her private credential: choose option 8
9. Bob verifies the proof: choose option 9

10. Issuer revokes Bpb's membership: choose option 10
11. Alice updates her private credential (membership witness) and local copy of schema: choose option  11
12. Bob updates his local copy of schema: choose option 11. Since Bob is revoked, Bob will not be able to update his private credential.

13. Bob requests a proof from Alice: choose option 7
14. Alice creates a proof: choose option 8
15. Bob verifies the proof: choose option 9. The proof verification should be successful.

16. Alice requests a proof from Bob: choose option 7
17. Bob creates a proof: choose option 8
18. Alice verifies the proof: choose option 9. The proof verification should fail since Bob is no longer a valid member.
```


