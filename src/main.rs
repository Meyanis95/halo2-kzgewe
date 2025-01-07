use halo2curves::CurveAffine;
use rand::rngs::OsRng;
use std::io::Cursor;

use ark_ec::{pairing::Pairing, CurveGroup, VariableBaseMSM};

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::{
        create_proof, keygen_pk, keygen_vk, Advice, Circuit, Column, ConstraintSystem, ErrorFront,
    },
    poly::{
        commitment::{CommitmentScheme, Params},
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::ProverGWC,
        },
        EvaluationDomain,
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptRead, TranscriptReadBuffer,
        TranscriptWriterBuffer,
    },
};

// Function to extract commitments for advice columns from a proof
fn extract_commitments<C: CommitmentScheme>(
    proof: &[u8],
    num_advice_columns: usize,
) -> Vec<halo2curves::bn256::G1Affine> {
    // Initialize the transcript reader with the proof data
    let mut transcript =
        Blake2bRead::<std::io::Cursor<&[u8]>, _, Challenge255<_>>::init(Cursor::new(proof));

    // Vector to store the extracted commitments
    let mut commitments = Vec::new();

    // Loop through the number of advice columns and read each commitment
    for _ in 0..num_advice_columns {
        let commitment = transcript.read_point().expect("Failed to read commitment");
        commitments.push(commitment);
    }

    // Return the vector of commitments
    commitments
}

/// CommitmentKey for KZG
pub struct CommitmentKey<E: Pairing> {
    pub lagranges: Vec<E::G1Affine>, // Precomputed Lagrange basis points in G1
}

/// Compute a KZG commitment for the given vector of evaluations
pub fn plain_kzg_com<E: Pairing>(ck: &CommitmentKey<E>, evals: &[E::ScalarField]) -> E::G1Affine {
    assert_eq!(evals.len(), ck.lagranges.len());
    let c = <E::G1 as VariableBaseMSM>::msm(&ck.lagranges, evals).unwrap();
    c.into_affine()
}

/// A simple configuration struct that holds one Advice column.
#[derive(Clone, Debug)]
struct MyConfig {
    advice_col: Column<Advice>,
}

/// A trivial circuit with just one witness `a`.
/// In a real circuit, `a` could be something you want to prove knowledge of.
#[derive(Clone, Debug)]
struct BitvectorCommitmentCircuit {
    /// This will be our witness. We store it as a `Value<Fp>`.
    bitvector: Vec<Value<Fr>>,
}

impl Circuit<Fr> for BitvectorCommitmentCircuit {
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

    // 2. Define the bit vector we want to commit (e.g., [1, 0, 1])
    let bitvector = vec![
        Value::known(Fr::from(1u64)),
        Value::known(Fr::from(0u64)),
        Value::known(Fr::from(1u64)),
    ];

    // 3. Create circuit instance with the bit vector
    let circuit = BitvectorCommitmentCircuit { bitvector };

    // 4. Generate universal (trusted) parameters for KZG
    let params: ParamsKZG<Bn256> = ParamsKZG::setup(k, &mut OsRng);

    // 5. Create verifying and proving keys
    let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail");

    // 6. Create a transcript for the proof
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);

    // 7. Actually create the proof (this is where polynomials get committed internally)
    create_proof::<KZGCommitmentScheme<_>, ProverGWC<_>, _, _, _, BitvectorCommitmentCircuit>(
        &params,
        &pk,
        &[circuit],
        &[(&[]).to_vec()],
        OsRng,
        &mut transcript,
    )
    .expect("proof generation should succeed");

    // 8. Finalize and serialize the proof
    let proof = transcript.finalize();
    println!("Proof created successfully!");

    // 9. Extract our advice column commtiment from the proof
    let num_advice_columns = 1; // Number of advice columns in the circuit
    let commitments = extract_commitments::<KZGCommitmentScheme<Bn256>>(&proof, num_advice_columns);

    // Commitment from Halo2
    let halo2_commitment = commitments[0];
    println!(
        "Halo2 Commitment to the bitvector column: {:?}",
        halo2_commitment
    );

    // 10. Compute the commitment from the bitvector using plain KZG
    let domain = EvaluationDomain::<Fr>::new(1, k);

    let fresh_bitvector = vec![
        Value::known(Fr::from(1u64)),
        Value::known(Fr::from(0u64)),
        Value::known(Fr::from(1u64)),
    ];

    // Convert the bitvector into a polynomial in Lagrange basis
    let mut poly = domain.empty_lagrange();
    for (i, val) in fresh_bitvector.iter().enumerate() {
        poly[i] = val.assign().unwrap();
    }

    println!("Polynomial: {:?}", poly);

    // Compute the commitment using `ParamsKZG`'s `commit_lagrange` function
    let engine = halo2_middleware::zal::impls::H2cEngine::new(); // Use the correct MsmAccel engine
    let commitment = params.commit_lagrange(
        &engine,
        &poly,
        halo2_proofs::poly::commitment::Blind(Fr::zero()),
    );

    let plain_commitment = G1Affine::from_xy(commitment.x, commitment.y).unwrap();

    println!("Commitment to the bitvector: {:?}", plain_commitment);

    // Compare our commitments
    assert_eq!(halo2_commitment, plain_commitment);
}
