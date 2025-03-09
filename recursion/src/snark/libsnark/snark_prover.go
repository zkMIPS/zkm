package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"text/template"

	"math/big"
	"os"
	"time"

	"github.com/succinctlabs/gnark-plonky2-verifier/types"
	"github.com/succinctlabs/gnark-plonky2-verifier/variables"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type SnarkProver struct {
	r1cs_circuit constraint.ConstraintSystem
	pk           groth16.ProvingKey
	vk           groth16.VerifyingKey
}

func (obj *SnarkProver) loadKeys(inputdir string) error {
	if obj.r1cs_circuit != nil {
		return nil
	}

	circuitPath := inputdir + "/circuit"
	pkPath := inputdir + "/proving.key"
	vkPath := inputdir + "/verifying.key"
	_, err := os.Stat(circuitPath)

	if err == nil {
		fCircuit, err := os.Open(circuitPath)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		obj.r1cs_circuit = groth16.NewCS(ecc.BN254)
		obj.r1cs_circuit.ReadFrom(fCircuit)
		fCircuit.Close()
	} else if os.IsNotExist(err) {
		return fmt.Errorf("snark: doesn't find the circuit file in %s.", inputdir)
	} else {
		// Handle other potential errors, such as permission issues
		return fmt.Errorf("snark: no permission to read the circuit file. ")
	}

	_, err = os.Stat(pkPath)
	
	if err == nil {
		obj.pk = groth16.NewProvingKey(ecc.BN254)
		obj.vk = groth16.NewVerifyingKey(ecc.BN254)
		fPk, err := os.Open(pkPath)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		obj.pk.ReadFrom(fPk)

		fVk, err := os.Open(vkPath)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		obj.vk.ReadFrom(fVk)
		defer fVk.Close()
	} else if os.IsNotExist(err) {
		return fmt.Errorf("snark: doesn't find the pk file in %s.", inputdir)
		
	} else {
		// Handle other potential errors, such as permission issues
		return fmt.Errorf("snark: no permission to read the pk file. ")
	}  
	return nil
}

func (obj *SnarkProver) groth16ProofWithCache(r1cs constraint.ConstraintSystem, inputdir, outputdir string) error {
	proofWithPisData, _ := types.ReadProofWithPublicInputs(inputdir + "/proof_with_public_inputs.json")
	proofWithPis := variables.DeserializeProofWithPublicInputs(proofWithPisData)

	verifierOnlyCircuitRawData, _ := types.ReadVerifierOnlyCircuitData(inputdir + "/verifier_only_circuit_data.json")
	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(verifierOnlyCircuitRawData)

	assignment := verifier.ExampleVerifierCircuit{
		PublicInputsHash:        proofWithPis.PublicInputsHash,
		Proof:                   proofWithPis.Proof,
		PublicInputs:            proofWithPis.PublicInputs,
		VerifierOnlyCircuitData: verifierOnlyCircuitData,
	}

	start := time.Now()
	fmt.Println("Generating witness", start)
	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	fmt.Printf("frontend.NewWitness cost time: %v ms\n", time.Since(start).Milliseconds())
	publicWitness, _ := witness.Public()

	start = time.Now()
	fmt.Println("Creating proof", start)
	proof, err := groth16.Prove(r1cs, obj.pk, witness)
	fmt.Printf("groth16.Prove cost time: %v ms\n", time.Since(start).Milliseconds())
	if err != nil {
		return err
	}

	if obj.vk == nil {
		return fmt.Errorf("vk is nil, means you're using dummy setup and we skip verification of proof")
	}

	start = time.Now()
	fmt.Println("Verifying proof", start)
	err = groth16.Verify(proof, obj.vk, publicWitness)
	fmt.Printf("groth16.Verify cost time: %v ms\n", time.Since(start).Milliseconds())
	if err != nil {
		return err
	}

	fContractProof, _ := os.Create(outputdir + "/snark_proof_with_public_inputs.json")
	_, bPublicWitness, _, _ := groth16.GetBn254Witness(proof, obj.vk, publicWitness)
	nbInputs := len(bPublicWitness)

	type ProofPublicData struct {
		Proof         groth16.Proof
		PublicWitness []string
	}
	proofPublicData := ProofPublicData{
		Proof:         proof,
		PublicWitness: make([]string, nbInputs),
	}
	for i := 0; i < nbInputs; i++ {
		input := new(big.Int)
		bPublicWitness[i].BigInt(input)
		proofPublicData.PublicWitness[i] = input.String()
	}
	proofData, _ := json.Marshal(proofPublicData)
	fContractProof.Write(proofData)
	fContractProof.Close()
	return nil
}

func (obj *SnarkProver) generateVerifySol(inputDir string) error {
	tmpl, err := template.New("contract").Parse(Gtemplate)
	if err != nil {
		return err
	}

	type VerifyingKeyConfig struct {
		Alpha     string
		Beta      string
		Gamma     string
		Delta     string
		Digest    string
		Gamma_abc string
		Sigmas    string
		Len       int
	}

	var config VerifyingKeyConfig
	vk := obj.vk.(*groth16_bn254.VerifyingKey)

	config.Alpha = fmt.Sprint("Pairing.G1Point(uint256(", vk.G1.Alpha.X.String(), "), uint256(", vk.G1.Alpha.Y.String(), "))")
	config.Beta = fmt.Sprint("Pairing.G2Point([uint256(", vk.G2.Beta.X.A0.String(), "), uint256(", vk.G2.Beta.X.A1.String(), ")], [uint256(", vk.G2.Beta.Y.A0.String(), "), uint256(", vk.G2.Beta.Y.A1.String(), ")])")
	config.Gamma = fmt.Sprint("Pairing.G2Point([uint256(", vk.G2.Gamma.X.A0.String(), "), uint256(", vk.G2.Gamma.X.A1.String(), ")], [uint256(", vk.G2.Gamma.Y.A0.String(), "), uint256(", vk.G2.Gamma.Y.A1.String(), ")])")
	config.Delta = fmt.Sprint("Pairing.G2Point([uint256(", vk.G2.Delta.X.A0.String(), "), uint256(", vk.G2.Delta.X.A1.String(), ")], [uint256(", vk.G2.Delta.Y.A0.String(), "), uint256(", vk.G2.Delta.Y.A1.String(), ")])")
	config.Gamma_abc = fmt.Sprint("vk.gamma_abc = new Pairing.G1Point[](", len(vk.G1.K), ");\n")
	for k, v := range vk.G1.K {
		config.Gamma_abc += fmt.Sprint("        vk.gamma_abc[", k, "] = Pairing.G1Point(uint256(", v.X.String(), "), uint256(", v.Y.String(), "));\n")
	}

	// constant
	file, err := os.Open(inputDir + "/block_public_inputs.json")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer file.Close()

	rawBytes, _ := io.ReadAll(file)
	var publicInputsOnly types.PublicInputsOnly
	err = json.Unmarshal(rawBytes, &publicInputsOnly)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	piData := publicInputsOnly.PublicInputs[48:]
	circuitDIgest := obj.combineToBigInt(piData, 0)
	config.Digest = circuitDIgest.String()

	l := len(piData)/4 - 1
	config.Len = l

	config.Sigmas = fmt.Sprint("[\n")
	for i := 0; i < l; i++ {
		v := obj.combineToBigInt(piData, i*4+4)
		config.Sigmas += fmt.Sprint("\t\t\t", v)
		if i < l-1 {
			config.Sigmas += fmt.Sprint(",\n")
		}
	}
	config.Sigmas += fmt.Sprint("\n\t\t]")

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, config)
	if err != nil {
		return err
	}
	fSol, _ := os.Create(filepath.Join(inputDir, "verifier.sol"))
	_, err = fSol.Write(buf.Bytes())
	if err != nil {
		return err
	}
	fSol.Close()
	return nil
}

func (obj *SnarkProver) combineToBigInt(data []uint64, idx int) *big.Int {
	result := new(big.Int)

	for i := 0; i < 4; i++ {
		part := new(big.Int).SetUint64(data[idx+i])

		part.Lsh(part, uint(64*(3-i)))
		result.Add(result, part)
	}

	return result
}

func (obj *SnarkProver) SetupAndGenerateSolVerifier(inputdir string) error {
	circuitPath := inputdir + "/circuit"
	pkPath := inputdir + "/proving.key"
	vkPath := inputdir + "/verifying.key"
	_, err := os.Stat(circuitPath)

	if os.IsNotExist(err) {
		commonCircuitData, _ := types.ReadCommonCircuitData(inputdir + "/common_circuit_data.json")
		proofWithPisData, _ := types.ReadProofWithPublicInputs(inputdir + "/proof_with_public_inputs.json")
		proofWithPis := variables.DeserializeProofWithPublicInputs(proofWithPisData)

		verifierOnlyCircuitRawData, _ := types.ReadVerifierOnlyCircuitData(inputdir + "/verifier_only_circuit_data.json")
		verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(verifierOnlyCircuitRawData)

		circuit := verifier.ExampleVerifierCircuit{
			PublicInputsHash:        proofWithPis.PublicInputsHash,
			Proof:                   proofWithPis.Proof,
			PublicInputs:            proofWithPis.PublicInputs,
			VerifierOnlyCircuitData: verifierOnlyCircuitData,
			CommonCircuitData:       commonCircuitData,
		}

		var builder frontend.NewBuilder = r1cs.NewBuilder
		obj.r1cs_circuit, _ = frontend.Compile(ecc.BN254.ScalarField(), builder, &circuit)
		fR1CS, _ := os.Create(circuitPath)
		obj.r1cs_circuit.WriteTo(fR1CS)
		fR1CS.Close()
	}

	_, err = os.Stat(pkPath)
	if os.IsNotExist(err) {
		obj.pk, obj.vk, err = groth16.Setup(obj.r1cs_circuit)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		fPK, _ := os.Create(pkPath)
		obj.pk.WriteTo(fPK)
		fPK.Close()

		if obj.vk != nil {
			fVK, _ := os.Create(vkPath)
			obj.vk.WriteTo(fVK)
			fVK.Close()
		}
	}

	if err := obj.generateVerifySol(inputdir); err != nil {
		return err
	}

	
	return nil
}


func (obj *SnarkProver) Prove(keypath string, inputdir string, outputdir string) error {
	if err := obj.loadKeys(keypath); err != nil {
		return err
	}

	
	return obj.groth16ProofWithCache(obj.r1cs_circuit, inputdir, outputdir)
}
