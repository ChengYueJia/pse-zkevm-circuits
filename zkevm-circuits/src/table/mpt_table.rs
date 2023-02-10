use crate::table::{AssignTable, LookupTable};
use crate::witness::MptUpdates;
use eth_types::Field;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::plonk::{Any, SecondPhase};
use halo2_proofs::{
    circuit::{Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error},
};
use itertools::Itertools;

/// The MptTable shared between MPT Circuit and State Circuit
#[derive(Clone, Copy, Debug)]
pub struct MptTable([Column<Advice>; 7]);

/// Table load arguments
pub(crate) struct MptTableLoadArgs<'a, F: Field> {
    /// MptUpdates Values
    pub(crate) updates: &'a MptUpdates,
    /// Randomness
    pub(crate) randomness: Value<F>,
}

impl<'a, F: Field> AssignTable<F> for MptTable {
    const TABLE_NAME: &'static str = "mpt table";
    type TableRowValue = [Value<F>; 7];
    type LoadArgs = MptTableLoadArgs<'a, F>;
    type AssignmentsArgs = ();

    /// Construct a new MptTable
    fn construct<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self {
        Self([
            meta.advice_column(),               // Address
            meta.advice_column_in(SecondPhase), // Storage key
            meta.advice_column(),               // Proof type
            meta.advice_column_in(SecondPhase), // New root
            meta.advice_column_in(SecondPhase), // Old root
            meta.advice_column_in(SecondPhase), // New value
            meta.advice_column_in(SecondPhase), // Old value
        ])
    }

    fn assignments<F: Field>(&self, args: Self::AssignmentsArgs) -> Vec<Self::TableRowValue> {
        todo!()
    }

    fn load(&self, layouter: &mut impl Layouter<F>, args: Self::LoadArgs) -> Result<(), Error> {
        layouter.assign_region(
            || format!("assign {}", Self::TABLE_NAME),
            |mut region| {
                let mut offset: usize = 0;
                self.assign_row(&mut region, offset, [Value::known(F::zero()); 7])?;

                offset += 1;
                for row in args.updates.table_assignments(args.randomness).iter() {
                    self.assign_row(&mut region, offset, row.0)?;

                    offset += 1;
                }
                Ok(())
            },
        )
    }
}

impl<F: Field> LookupTable<F> for MptTable {
    fn columns(&self) -> Vec<Column<Any>> {
        self.0.iter().map(|&col| col.into()).collect()
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("Address"),
            String::from("Storage key"),
            String::from("Proof type"),
            String::from("New root"),
            String::from("Old root"),
            String::from("New value"),
            String::from("Old value"),
        ]
    }
}
