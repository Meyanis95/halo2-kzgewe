use std::io::Cursor;

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    halo2curves::bn256::{Bn256, Fr},
    plonk::{
        create_proof, keygen_pk, keygen_vk, Advice, Circuit, Column, ConstraintSystem, ErrorFront,
    },
    poly::{
        commitment::CommitmentScheme,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::ProverGWC,
        },
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptRead, TranscriptReadBuffer,
        TranscriptWriterBuffer,
    },
};
use rand::rngs::OsRng; // This uses the Pasta Fp field from the Halo2 repo

// Helper to get our advice column commitments from the proof
fn extract_commitments<C: CommitmentScheme>(
    proof: &[u8],
    num_advice_columns: usize,
) -> Vec<halo2curves::bn256::G1Affine> {
    let mut transcript =
        Blake2bRead::<std::io::Cursor<&[u8]>, _, Challenge255<_>>::init(Cursor::new(proof));

    // Read commitments for advice columns
    let mut commitments = Vec::new();
    for _ in 0..num_advice_columns {
        let commitment = transcript.read_point().expect("Failed to read commitment");
        commitments.push(commitment);
    }
    commitments
}

/// A simple configuration struct that holds one Advice column.
#[derive(Clone, Debug)]
struct MyConfig {
    advice_col: Column<Advice>,
}

/// A trivial circuit with just one witness `a`.
/// In a real circuit, `a` could be something you want to prove knowledge of.
#[derive(Clone, Debug)]
struct MyCircuit {
    /// This will be our witness. We store it as a `Value<Fp>`.
    bitvector: Vec<Value<Fr>>,
}

impl Circuit<Fr> for MyCircuit {
    type Config = MyConfig;
    type FloorPlanner = SimpleFloorPlanner;

    /// This is optional “empty” version of the circuit without witness values.
    fn without_witnesses(&self) -> Self {
        Self {
            bitvector: vec![Value::unknown()],
        }
    }

    /// Configure is where you define circuit structure: which columns exist,
    /// what selectors you need, and how constraints are applied.
    fn configure(meta: &mut ConstraintSystem<Fr>) -> MyConfig {
        // Allocate a single advice column.
        let advice_col = meta.advice_column();

        // For demonstration, we enable equality on the advice column.
        // This allows equality checks or copying the cell across rows or columns.
        meta.enable_equality(advice_col);

        MyConfig { advice_col }
    }

    /// `synthesize` is where you lay out your circuit’s values.
    fn synthesize(
        &self,
        config: MyConfig,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), ErrorFront> {
        // Assign a value to the advice column in row 0.
        layouter.assign_region(
            || "Assign bit vector",
            |mut region| {
                for (i, bit) in self.bitvector.iter().enumerate() {
                    region.assign_advice(|| format!("bit {}", i), config.advice_col, i, || *bit)?;
                }
                Ok(())
            },
        )?;

        Ok(())
    }
}

fn main() {
    // 1. Choose circuit size = 2^k
    let k = 5;

    // 1. Define the bit vector (e.g., [1, 0, 1])
    let bitvector = vec![
        Value::known(Fr::from(1u64)),
        Value::known(Fr::from(0u64)),
        Value::known(Fr::from(1u64)),
    ];

    // 2. Create circuit instance with the bit vector
    let circuit = MyCircuit { bitvector };

    // 3. Generate universal (trusted) parameters for KZG
    let params: ParamsKZG<Bn256> = ParamsKZG::setup(k, &mut OsRng);

    // 4. Create verifying and proving keys
    let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail");

    // 5. Create a transcript for the proof
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);

    // 6. Actually create the proof (this is where polynomials get committed internally)
    create_proof::<KZGCommitmentScheme<_>, ProverGWC<_>, _, _, _, MyCircuit>(
        &params,
        &pk,
        &[circuit],        // You can pass multiple circuits here
        &[(&[]).to_vec()], // Public inputs if any
        OsRng,
        &mut transcript,
    )
    .expect("proof generation should succeed");

    // 6. Finalize and serialize the proof
    let proof = transcript.finalize();
    println!("Proof created successfully!");

    // 7. Extract commitments
    let num_advice_columns = 1; // Number of advice columns in the circuit
    let commitments = extract_commitments::<KZGCommitmentScheme<Bn256>>(&proof, num_advice_columns);

    // 8. Print the commitment to the bitvector column
    println!("Commitment to the bitvector column: {:?}", commitments[0]);
}
