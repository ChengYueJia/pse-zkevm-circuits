use crate::evm_circuit::util::rlc;
use crate::impl_expr;
use crate::table::{AssignTable, LoadTable, LookupTable};
use crate::util::random_linear_combine_word;
use crate::witness::BlockContext;
use eth_types::{Field, ToLittleEndian, ToScalar};
use halo2_proofs::{circuit::Layouter, plonk::*};
use halo2_proofs::{
    circuit::{Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error},
};
use itertools::Itertools;

/// Tag to identify the field in a Block Table row
// Keep the sequence consistent with OpcodeId for scalar
#[derive(Clone, Copy, Debug)]
pub enum BlockContextFieldTag {
    /// Unused tag
    Null = 0,
    /// Coinbase field
    Coinbase = 1,
    /// Timestamp field
    Timestamp,
    /// Number field
    Number,
    /// Difficulty field
    Difficulty,
    /// Gas Limit field
    GasLimit,
    /// Base Fee field
    BaseFee = 8,
    /// Block Hash field
    BlockHash,
    /// Chain ID field.  Although this is not a field in the block header, we
    /// add it here for convenience.
    ChainId,
}
impl_expr!(BlockContextFieldTag);

/// Table with Block header fields
#[derive(Clone, Debug)]
pub struct BlockTable {
    /// Tag
    pub tag: Column<Advice>,
    /// Index
    pub index: Column<Advice>,
    /// Value
    pub value: Column<Advice>,
}

/// Table load arguments
pub(crate) struct BlockTableLoadArgs<'a, F: Field> {
    /// Block Values
    pub(crate) block: &'a BlockContext,
    /// Randomness
    pub(crate) randomness: Value<F>,
}

impl<'a, F: Field> AssignTable<F> for BlockTable {
    const TABLE_NAME: &'static str = "block table";

    type TableRowValue = [Value<F>; 3];

    type LoadArgs = BlockTableLoadArgs<'a, F>;
    type AssignmentsArgs = BlockTableLoadArgs<'a, F>;

    /// Construct a new BlockTable
    fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            tag: meta.advice_column(),
            index: meta.advice_column(),
            value: meta.advice_column_in(SecondPhase),
        }
    }

    fn assignments<F: Field>(
        &self,
        Self::AssignmentsArgs { block, randomness }: Self::LoadArgs,
    ) -> Vec<Self::TableRowValue> {
        [
            vec![
                [
                    Value::known(F::from(BlockContextFieldTag::Coinbase as u64)),
                    Value::known(F::zero()),
                    Value::known(block.coinbase.to_scalar().unwrap()),
                ],
                [
                    Value::known(F::from(BlockContextFieldTag::Timestamp as u64)),
                    Value::known(F::zero()),
                    Value::known(block.timestamp.to_scalar().unwrap()),
                ],
                [
                    Value::known(F::from(BlockContextFieldTag::Number as u64)),
                    Value::known(F::zero()),
                    Value::known(block.number.to_scalar().unwrap()),
                ],
                [
                    Value::known(F::from(BlockContextFieldTag::Difficulty as u64)),
                    Value::known(F::zero()),
                    randomness
                        .map(|randomness| rlc::value(&block.difficulty.to_le_bytes(), randomness)),
                ],
                [
                    Value::known(F::from(BlockContextFieldTag::GasLimit as u64)),
                    Value::known(F::zero()),
                    Value::known(F::from(block.gas_limit)),
                ],
                [
                    Value::known(F::from(BlockContextFieldTag::BaseFee as u64)),
                    Value::known(F::zero()),
                    randomness
                        .map(|randomness| rlc::value(&block.base_fee.to_le_bytes(), randomness)),
                ],
                [
                    Value::known(F::from(BlockContextFieldTag::ChainId as u64)),
                    Value::known(F::zero()),
                    randomness
                        .map(|randomness| rlc::value(&block.chain_id.to_le_bytes(), randomness)),
                ],
            ],
            {
                let len_history = block.history_hashes.len();
                block
                    .history_hashes
                    .iter()
                    .enumerate()
                    .map(|(idx, hash)| {
                        [
                            Value::known(F::from(BlockContextFieldTag::BlockHash as u64)),
                            Value::known((block.number - len_history + idx).to_scalar().unwrap()),
                            randomness
                                .map(|randomness| rlc::value(&hash.to_le_bytes(), randomness)),
                        ]
                    })
                    .collect()
            },
        ]
        .concat()
    }

    fn load(&self, layouter: &mut impl Layouter<F>, args: Self::LoadArgs) -> Result<(), Error> {
        layouter.assign_region(
            || format!("assign {}", Self::TABLE_NAME),
            |mut region| {
                let mut offset = 0;

                self.assign_row(&mut region, offset, [Value::known(F::zero()); 3])?;

                offset += 1;
                for row in self.assignments(args) {
                    self.assign_row(&mut region, offset, row)?;
                    offset += 1;
                }
                Ok(())
            },
        )
    }
}

impl<F: Field> LookupTable<F> for BlockTable {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![self.tag.into(), self.index.into(), self.value.into()]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("tag"),
            String::from("index"),
            String::from("value"),
        ]
    }
}
