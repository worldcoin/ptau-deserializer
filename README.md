# ptau-deserializer

.zkey and .ptau deserializer for gnark groth16 bn254 trusted setup

## Usage

Convert a `.ptau` file to a `.ph1` file:

```bash
go run main.go convert --input <CEREMONY>.ptau --output <CEREMONY>.ph1
```

Initialize phase2 of the trusted setup ceremony using the [`semaphore-mtb-setup` coordinator](https://github.com/worldcoin/semaphore-mtb-setup/) (wrapper of [`gnark/backend/groth16/bn254/mpcsetup`](https://github.com/ConsenSys/gnark/tree/develop/backend/groth16/bn254/mpcsetup)):

```bash
go run main.go initialize --input <FILE>.ph1 --r1cs <CIRCUIT>.r1cs --output <FILE>.ph2
```

## Setup

Download a `.zkey` file from the [PSE Snark artifact page for semaphore](https://www.trusted-setup-pse.org/#Semaphore) by running the following command:

```bash
wget https://www.trusted-setup-pse.org/semaphore/16/semaphore.zkey -O deserialize/semaphore_16.zkey
```

Download the `.ptau` file from the [`snarkjs` repository](https://github.com/iden3/snarkjs#7-prepare-phase-2) by running the following command:

```bash
wget https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_08.ptau -O deserialize/08.ptau
```

For larger `.ptau` files, checkout the `snarkjs` repository's [README](https://github.com/iden3/snarkjs/tree/master#7-prepare-phase-2) for more information.

Remember that you need sufficiently high powers of tau ceremony to generate a proof for a circuit with a given amount of constraints:

```text
2^{POWERS_OF_TAU} >= CONSTRAINTS
```

To get a sample r1cs file from `semaphore-mtb`, checkout the [`semaphore-mtb` repository](https://github.com/worldcoin/semaphore-mtb.git) and run the following command:

```bash
git clone https://github.com/worldcoin/semaphore-mtb.git
go build
./gnark-mbu r1cs --mode insertion --tree-depth=10 --batch-size=15 --output=demo_insertion_smtb.r1cs
./gnark-mbu r1cs --mode deletion --tree-depth=10 --batch-size=15 --output=demo_deletion_smtb.r1cs
```

Move the file to into `deserialize` directory:

```bash
mv semaphore-mtb/demo_smtb.r1cs ptau-deserializer/deserialize/demo_smtb.r1cs
```

If you want to see the byte representation of the `.ptau` file, run the following command:

```bash
hexdump -C deserialize/08.ptau > deserialize/08.ptau.hex
```

Same applies for the `.zkey` file:

```bash
hexdump -C deserialize/semaphore_16.zkey > deserialize/semaphore_16.zkey.hex
```

## Testing

To test, run:

```bash
cd deserialize && go test -v
```
