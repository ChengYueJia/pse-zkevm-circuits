use crate::evm_circuit::util::{rlc, RandomLinearCombination};
use crate::table::{AssignTable, LookupTable};
use crate::util::Challenges;
use eth_types::{Field, ToLittleEndian, Word};
use halo2_proofs::plonk::Any;
use halo2_proofs::{
    circuit::{Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, SecondPhase},
};
use itertools::Itertools;
use keccak256::plain::Keccak;

/// Keccak Table, used to verify keccak hashing from RLC'ed input.
#[derive(Clone, Debug)]
pub struct KeccakTable {
    /// True when the row is enabled
    pub is_enabled: Column<Advice>,
    /// Byte array input as `RLC(reversed(input))`
    pub input_rlc: Column<Advice>,
    // RLC of input bytes
    /// Byte array input length
    pub input_len: Column<Advice>,
    /// RLC of the hash result
    pub output_rlc: Column<Advice>, // RLC of hash of input bytes
}

type KeccakTableRow = [Value<F>; 4];

impl KeccakTable {
    /// Generate the keccak table assignments from a byte array input.
    pub fn assignments<F: Field>(
        input: &[u8],
        challenges: &Challenges<Value<F>>,
    ) -> Vec<KeccakTableRow> {
        let input_rlc = challenges
            .keccak_input()
            .map(|challenge| rlc::value(input.iter().rev(), challenge));
        let input_len = F::from(input.len() as u64);
        let mut keccak = Keccak::default();
        keccak.update(input);
        let output = keccak.digest();
        let output_rlc = challenges.evm_word().map(|challenge| {
            rlc::value(
                &Word::from_big_endian(output.as_slice()).to_le_bytes(),
                challenge,
            )
        });

        vec![[
            Value::known(F::one()),
            input_rlc,
            Value::known(input_len),
            output_rlc,
        ]]
    }

    /// Provide this function for the case that we want to consume a keccak
    /// table but without running the full keccak circuit
    pub fn dev_load<'a, F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        inputs: impl IntoIterator<Item = &'a Vec<u8>> + Clone,
        challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "keccak table",
            |mut region| {
                let mut offset = 0;

                self.assign_row(&mut region, offset, [Value::known(F::zero()); 4])?;

                offset += 1;

                for input in inputs.clone() {
                    for row in Self::assignments(input, challenges) {
                        // let mut column_index = 0;
                        self.assign_row(&mut region, offset, row)?;
                        offset += 1;
                    }
                }
                Ok(())
            },
        )
    }

    /// returns matchings between the circuit columns passed as parameters and
    /// the table collumns
    pub fn match_columns(
        &self,
        value_rlc: Column<Advice>,
        length: Column<Advice>,
        code_hash: Column<Advice>,
    ) -> Vec<(Column<Advice>, Column<Advice>)> {
        vec![
            (value_rlc, self.input_rlc),
            (length, self.input_len),
            (code_hash, self.output_rlc),
        ]
    }
}

impl<F: Field> AssignTable<F> for KeccakTable {
    const TABLE_NAME: &'static str = "keccak table";
    type TableRowValue = KeccakTableRow;
    type LoadArgs = ();
    type AssignmentsArgs = ();

    /// Construct a new KeccakTable
    fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            is_enabled: meta.advice_column(),
            input_rlc: meta.advice_column_in(SecondPhase),
            input_len: meta.advice_column(),
            output_rlc: meta.advice_column_in(SecondPhase),
        }
    }

    // TODO unify table load logic here and keccak circuit.
    fn assignments<F: Field>(&self, args: Self::LoadArgs) -> Vec<Self::TableRowValue> {
        todo!()
    }

    // TODO unify table load logic here and keccak circuit.
    fn load(&self, layouter: &mut impl Layouter<F>, args: Self::LoadArgs) -> Result<(), Error> {
        todo!()
    }
}
impl<F: Field> LookupTable<F> for KeccakTable {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![
            self.is_enabled.into(),
            self.input_rlc.into(),
            self.input_len.into(),
            self.output_rlc.into(),
        ]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("is_enabled"),
            String::from("input_rlc"),
            String::from("input_len"),
            String::from("output_rlc"),
        ]
    }
}
