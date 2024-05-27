package deserializer

import (
	"fmt"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/stretchr/testify/require"
)

type TestCircuit struct {
	A, B, C frontend.Variable
}

func (circuit *TestCircuit) Define(api frontend.API) error {
	prod := api.Mul(circuit.A, circuit.B)
	api.AssertIsEqual(circuit.C, prod)
	api.AssertIsEqual(circuit.A, circuit.B)
	return nil
}

///////////////////////////////////////////////////////////////////
///                             PTAU                            ///
///////////////////////////////////////////////////////////////////

// Format
// Taken from the iden3/snarkjs repo powersoftau_new.js file
// https://github.com/iden3/snarkjs/blob/master/src/powersoftau_new.js
/*
Header(1)
    n8
    prime
    power
tauG1(2)
    {(2 ** power)*2-1} [
        G1, tau*G1, tau^2 * G1, ....
    ]
tauG2(3)
    {2 ** power}[
        G2, tau*G2, tau^2 * G2, ...
    ]
alphaTauG1(4)
    {2 ** power}[
        alpha*G1, alpha*tau*G1, alpha*tau^2*G1,....
    ]
betaTauG1(5)
    {2 ** power} []
        beta*G1, beta*tau*G1, beta*tau^2*G1, ....
    ]
betaG2(6)
    {1}[
        beta*G2
    ]
contributions(7) - Ignore contributions, users can verify using snarkjs
    NContributions
    {NContributions}[
        tau*G1
        tau*G2
        alpha*G1
        beta*G1
        beta*G2
        pubKey
            tau_g1s
            tau_g1sx
            tau_g2spx
            alpha_g1s
            alpha_g1sx
            alpha_g1spx
            beta_g1s
            beta_g1sx
            beta_g1spx
        partialHash (216 bytes) See https://github.com/mafintosh/blake2b-wasm/blob/23bee06945806309977af802bc374727542617c7/blake2b.wat#L9
        hashNewChallenge
    ]
*/

const r1csFilePath = "test.r1cs"

func TestSerializeR1CS(t *testing.T) {
	assert := require.New(t)
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &TestCircuit{})
	assert.NoError(err)
	file, err := os.Create(r1csFilePath)
	defer file.Close()
	assert.NoError(err)
	_, err = ccs.WriteTo(file)
	assert.NoError(err)
}

///////////////////////////////////////////////////////////////////
///                             ZKEY                            ///
///////////////////////////////////////////////////////////////////

// Taken from the iden3/snarkjs repo, zkey_utils.js
// (https://github.com/iden3/snarkjs/blob/fb144555d8ce4779ad79e707f269771c672a8fb7/src/zkey_utils.js#L20-L45)
// Format
// ======
// 4 bytes, zket
// 4 bytes, version
// 4 bytes, number of sections
// 4 bytes, section number
// 8 bytes, section size
// Header(1)
// 4 bytes, Prover Type 1 Groth
// HeaderGroth(2)
// 4 bytes, n8q
// n8q bytes, q
// 4 bytes, n8r
// n8r bytes, r
// 4 bytes, NVars
// 4 bytes, NPub
// 4 bytes, DomainSize  (multiple of 2)
//      alpha1
//      beta1
//      delta1
//      beta2
//      gamma2
//      delta2

func TestDeserializerZkey(t *testing.T) {
	input_path := "semaphore_16.zkey"

	assert := require.New(t)

	zkey, err := ReadZkey(input_path)
	if err != nil {
		assert.NoError(err)
	}

	fmt.Printf("ProtocolID for Groth16: %v \n", zkey.ZkeyHeader.ProtocolID)

	// protocolID should be 1 (Groth16)
	assert.Equal(GROTH_16_PROTOCOL_ID, zkey.ZkeyHeader.ProtocolID)

	fmt.Printf("n8q is: %v \n", zkey.protocolHeader.n8q)

	fmt.Printf("q is: %v \n", zkey.protocolHeader.q.String())

	fmt.Printf("n8r is: %v \n", zkey.protocolHeader.n8r)

	fmt.Printf("r is: %v \n", zkey.protocolHeader.r.String())

	fmt.Printf("nVars is: %v \n", zkey.protocolHeader.nVars)

	fmt.Printf("nPublic is: %v \n", zkey.protocolHeader.nPublic)

	fmt.Printf("domainSize is: %v \n", zkey.protocolHeader.domainSize)

	fmt.Printf("power is: %v \n", zkey.protocolHeader.power)
}
