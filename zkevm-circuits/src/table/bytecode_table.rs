use crate::evm_circuit::util::{rlc, RandomLinearCombination};
use crate::impl_expr;
use crate::table::{AssignTable, LookupTable};
use crate::util::Challenges;
use crate::witness::Bytecode;
use eth_types::evm_types::OpcodeId;
use eth_types::{Field, ToLittleEndian};
use halo2_proofs::{circuit::Layouter, plonk::*};
use halo2_proofs::{
    circuit::{Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error},
};
use itertools::Itertools;
use std::array;

/// Tag to identify the field in a Bytecode Table row
#[derive(Clone, Copy, Debug)]
pub enum BytecodeFieldTag {
    /// Header field
    Header,
    /// Byte field
    Byte,
}
impl_expr!(BytecodeFieldTag);

/// Table with Bytecode indexed by its Code Hash
#[derive(Clone, Debug)]
pub struct BytecodeTable {
    /// Code Hash
    pub code_hash: Column<Advice>,
    /// Tag
    pub tag: Column<Advice>,
    /// Index
    pub index: Column<Advice>,
    /// Is Code is true when the byte is not an argument to a PUSH* instruction.
    pub is_code: Column<Advice>,
    /// Value
    pub value: Column<Advice>,
}

/// Table load arguments
pub(crate) struct BytecodeTableLoadArgs<'a, F: Field> {
    /// Bytecodes Values. Used for load method
    pub(crate) bytecodes: Vec<&'a Bytecode>,
    /// Challenges
    pub(crate) challenges: Challenges<Value<F>>,
}

/// Table assignments arguments
pub(crate) struct BytecodeTableAssignmentsArgs<'b, F: Field> {
    /// Bytecode Values. Used for assignments method
    pub(crate) bytecode: &'b Bytecode,
    /// Challenges
    pub(crate) challenges: Challenges<Value<F>>,
}

impl<'a, 'b, F: Field> AssignTable<F> for BytecodeTable {
    const TABLE_NAME: &'static str = "bytecode table";
    type TableRowValue = [Value<F>; 5];
    type LoadArgs = BytecodeTableLoadArgs<'a, F>;
    type AssignmentsArgs = BytecodeTableAssignmentsArgs<'b, F>;

    /// Construct a new BytecodeTable
    fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        let [tag, index, is_code, value] = array::from_fn(|_| meta.advice_column());
        let code_hash = meta.advice_column_in(SecondPhase);
        Self {
            code_hash,
            tag,
            index,
            is_code,
            value,
        }
    }

    fn assignments<F: Field>(&self, args: Self::AssignmentsArgs) -> Vec<Self::TableRowValue> {
        let bytecode = args.bytecode;

        let n = 1 + bytecode.bytes.len();
        let mut rows = Vec::with_capacity(n);
        let hash = args
            .challenges
            .evm_word()
            .map(|challenge| rlc::value(&bytecode.hash.to_le_bytes(), challenge));

        rows.push([
            hash,
            Value::known(F::from(BytecodeFieldTag::Header as u64)),
            Value::known(F::zero()),
            Value::known(F::zero()),
            Value::known(F::from(bytecode.bytes.len() as u64)),
        ]);

        let mut push_data_left = 0;
        for (idx, byte) in bytecode.bytes.iter().enumerate() {
            let is_code = push_data_left == 0;

            push_data_left = if is_code {
                // push_data_left will be > 0 only if it is a push opcode
                OpcodeId::from(*byte).data_len()
            } else {
                push_data_left - 1
            };

            rows.push([
                hash,
                Value::known(F::from(BytecodeFieldTag::Byte as u64)),
                Value::known(F::from(idx as u64)),
                Value::known(F::from(is_code as u64)),
                Value::known(F::from(*byte as u64)),
            ])
        }
        rows
    }

    /// Assign the `BytecodeTable` from a list of bytecodes, followig the same
    /// table layout that the Bytecode Circuit uses.
    fn load(&self, layouter: &mut impl Layouter<F>, args: Self::LoadArgs) -> Result<(), Error> {
        layouter.assign_region(
            || format!("assign {}", Self::TABLE_NAME),
            |mut region| {
                let mut offset = 0;

                // assign zero row
                self.assign_row(&mut region, offset, [Value::known(F::zero()); 5])?;

                offset += 1;

                for bytecode in args.bytecodes {
                    for row in self.assignments(Self::AssignmentsArgs {
                        bytecode,
                        challenges,
                    }) {
                        self.assign_row(&mut region, offset, row)?;

                        offset += 1;
                    }
                }
                Ok(())
            },
        )
    }
}

impl<F: Field> LookupTable<F> for BytecodeTable {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![
            self.code_hash.into(),
            self.tag.into(),
            self.index.into(),
            self.is_code.into(),
            self.value.into(),
        ]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("code_hash"),
            String::from("tag"),
            String::from("index"),
            String::from("is_code"),
            String::from("value"),
        ]
    }
}
