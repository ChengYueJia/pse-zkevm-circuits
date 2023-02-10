use crate::exp_circuit::{OFFSET_INCREMENT, ROWS_PER_STEP};
use crate::table::{AssignTable, LookupTable};
use crate::witness::Block;
use bus_mapping::circuit_input_builder::{CopyEvent, ExpEvent};
use eth_types::{Field, ToScalar, U256};
use gadgets::util::{split_u256, split_u256_limb64};
use halo2_proofs::{circuit::Layouter, plonk::*, poly::Rotation};
use halo2_proofs::{
    circuit::{Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error},
};
use itertools::Itertools;

/// Lookup table within the Exponentiation circuit.
#[derive(Clone, Copy, Debug)]
pub struct ExpTable {
    /// Whether the row is the start of a step.
    pub is_step: Column<Advice>,
    /// An identifier for every exponentiation trace, at the moment this is the
    /// read-write counter at the time of the lookups done to the
    /// exponentiation table.
    pub identifier: Column<Advice>,
    /// Whether this row is the last row in the exponentiation operation's
    /// trace.
    pub is_last: Column<Advice>,
    /// The integer base of the exponentiation.
    pub base_limb: Column<Advice>,
    /// The integer exponent of the exponentiation.
    pub exponent_lo_hi: Column<Advice>,
    /// The intermediate result of exponentiation by squaring.
    pub exponentiation_lo_hi: Column<Advice>,
}

/// Table load arguments
pub(crate) struct ExpTableLoadArgs<'a, F: Field> {
    /// Exp Values.
    pub(crate) exp_events: &'a Vec<ExpEvent>,
}

/// Table assignments arguments
pub(crate) struct ExpTableAssignmentsArgs<'b, F: Field> {
    /// Exp Values.
    pub(crate) exp_event: &'b ExpEvent,
}

impl ExpTable {
    pub(crate) fn load_with_region<'a, F: Field>(
        &self,
        region: &mut Region<'_, F>,
        args: ExpTableLoadArgs<'a, F>,
    ) -> Result<(), Error> {
        let mut offset = 0;
        <ExpTable as AssignTable<F>>::assign_row(self, region, offset, [F::zero(); 6])?;

        offset += 1;
        for exp_event in args.exp_events.iter() {
            for row in
                <ExpTable as AssignTable<F>>::assignments(self, Self::AssignmentsArgs { exp_event })
            {
                <ExpTable as AssignTable<F>>::assign_row(self, region, offset, row)?;
                offset += 1;
            }
        }
        Ok(())
    }
}

impl<'a, 'b, F: Field> AssignTable<F> for ExpTable {
    const TABLE_NAME: &'static str = "exponentiation table";
    type TableRowValue = [F; 6];
    type LoadArgs = ExpTableLoadArgs<'a, F>;
    type AssignmentsArgs = ExpTableAssignmentsArgs<'b, F>;

    /// Construct the Exponentiation table.
    fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            is_step: meta.advice_column(),
            identifier: meta.advice_column(),
            is_last: meta.advice_column(),
            base_limb: meta.advice_column(),
            exponent_lo_hi: meta.advice_column(),
            exponentiation_lo_hi: meta.advice_column(),
        }
    }

    /// Given an exponentiation event and randomness, get assignments to the
    /// exponentiation table.
    fn assignments<F: Field>(&self, args: Self::AssignmentsArgs) -> Vec<Self::TableRowValue> {
        let mut assignments = Vec::new();
        let base_limbs = split_u256_limb64(&exp_event.base);
        let identifier = F::from(exp_event.identifier as u64);
        let mut exponent = exp_event.exponent;
        for (step_idx, exp_step) in exp_event.steps.iter().rev().enumerate() {
            let is_last = if step_idx == exp_event.steps.len() - 1 {
                F::one()
            } else {
                F::zero()
            };
            let (exp_lo, exp_hi) = split_u256(&exp_step.d);
            let (exponent_lo, exponent_hi) = split_u256(&exponent);

            // row 1
            assignments.push([
                F::one(),
                identifier,
                is_last,
                base_limbs[0].as_u64().into(),
                exponent_lo
                    .to_scalar()
                    .expect("exponent should fit to scalar"),
                exp_lo
                    .to_scalar()
                    .expect("exponentiation lo should fit to scalar"),
            ]);
            // row 2
            assignments.push([
                F::zero(),
                identifier,
                F::zero(),
                base_limbs[1].as_u64().into(),
                exponent_hi
                    .to_scalar()
                    .expect("exponent hi should fit to scalar"),
                exp_hi
                    .to_scalar()
                    .expect("exponentiation hi should fit to scalar"),
            ]);
            // row 3
            assignments.push([
                F::zero(),
                identifier,
                F::zero(),
                base_limbs[2].as_u64().into(),
                F::zero(),
                F::zero(),
            ]);
            // row 4
            assignments.push([
                F::zero(),
                identifier,
                F::zero(),
                base_limbs[3].as_u64().into(),
                F::zero(),
                F::zero(),
            ]);
            for _ in ROWS_PER_STEP..OFFSET_INCREMENT {
                assignments.push([
                    F::zero(),
                    F::zero(),
                    F::zero(),
                    F::zero(),
                    F::zero(),
                    F::zero(),
                ]);
            }

            // update intermediate exponent.
            let (exponent_div2, remainder) = exponent.div_mod(U256::from(2));
            if remainder.is_zero() {
                // exponent is even
                exponent = exponent_div2;
            } else {
                // exponent is odd
                exponent = exponent - 1;
            }
        }
        assignments
    }

    fn load(&self, layouter: &mut impl Layouter<F>, args: Self::LoadArgs) -> Result<(), Error> {
        layouter.assign_region(
            || format!("assign {}", Self::TABLE_NAME),
            |mut region| self.load_with_region(&mut region, args),
        )
    }
}

impl<F: Field> LookupTable<F> for ExpTable {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![
            self.is_step.into(),
            self.identifier.into(),
            self.is_last.into(),
            self.base_limb.into(),
            self.exponent_lo_hi.into(),
            self.exponentiation_lo_hi.into(),
        ]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("is_step"),
            String::from("identifier"),
            String::from("is_last"),
            String::from("base_limb"),
            String::from("exponent_lo_hi"),
            String::from("exponentiation_lo_hi"),
        ]
    }

    fn table_exprs(&self, meta: &mut VirtualCells<F>) -> Vec<Expression<F>> {
        vec![
            meta.query_advice(self.is_step, Rotation::cur()),
            meta.query_advice(self.identifier, Rotation::cur()),
            meta.query_advice(self.is_last, Rotation::cur()),
            meta.query_advice(self.base_limb, Rotation::cur()),
            meta.query_advice(self.base_limb, Rotation::next()),
            meta.query_advice(self.base_limb, Rotation(2)),
            meta.query_advice(self.base_limb, Rotation(3)),
            meta.query_advice(self.exponent_lo_hi, Rotation::cur()),
            meta.query_advice(self.exponent_lo_hi, Rotation::next()),
            meta.query_advice(self.exponentiation_lo_hi, Rotation::cur()),
            meta.query_advice(self.exponentiation_lo_hi, Rotation::next()),
        ]
    }
}
