use crate::impl_expr;
use crate::table::{AssignTable, LookupTable};
use crate::util::Challenges;
use crate::witness::{Rw, RwMap, RwRow};
use eth_types::Field;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::plonk::*;
use halo2_proofs::{
    circuit::{Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error},
};
use itertools::Itertools;
use std::thread::sleep;
use strum_macros::EnumIter;

/// Tag to identify the operation type in a RwTable row
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, EnumIter)]
pub enum RwTableTag {
    /// Start (used for padding)
    Start = 1,
    /// Stack operation
    Stack,
    /// Memory operation
    Memory,
    /// Account Storage operation
    AccountStorage,
    /// Tx Access List Account operation
    TxAccessListAccount,
    /// Tx Access List Account Storage operation
    TxAccessListAccountStorage,
    /// Tx Refund operation
    TxRefund,
    /// Account operation
    Account,
    /// Account Destructed operation
    AccountDestructed,
    /// Call Context operation
    CallContext,
    /// Tx Log operation
    TxLog,
    /// Tx Receipt operation
    TxReceipt,
}
impl_expr!(RwTableTag);

impl RwTableTag {
    /// Returns true if the RwTable operation is reversible
    pub fn is_reversible(self) -> bool {
        matches!(
            self,
            RwTableTag::TxAccessListAccount
                | RwTableTag::TxAccessListAccountStorage
                | RwTableTag::TxRefund
                | RwTableTag::Account
                | RwTableTag::AccountStorage
                | RwTableTag::AccountDestructed
        )
    }
}

impl From<RwTableTag> for usize {
    fn from(t: RwTableTag) -> Self {
        t as usize
    }
}

/// The RwTable shared between EVM Circuit and State Circuit, which contains
/// traces of the EVM state operations.
#[derive(Clone, Copy, Debug)]
pub struct RwTable {
    /// Read Write Counter
    pub rw_counter: Column<Advice>,
    /// Is Write
    pub is_write: Column<Advice>,
    /// Tag
    pub tag: Column<Advice>,
    /// Key1 (Id)
    pub id: Column<Advice>,
    /// Key2 (Address)
    pub address: Column<Advice>,
    /// Key3 (FieldTag)
    pub field_tag: Column<Advice>,
    /// Key3 (StorageKey)
    pub storage_key: Column<Advice>,
    /// Value
    pub value: Column<Advice>,
    /// Value Previous
    pub value_prev: Column<Advice>,
    /// Aux1
    pub aux1: Column<Advice>,
    /// Aux2 (Committed Value)
    pub aux2: Column<Advice>,
}

/// Table load arguments
pub(crate) struct RwTableLoadArgs<'a, F: Field> {
    /// Rw Values.
    pub(crate) rws: &'a Vec<Rw>,
    /// The nums of padding rows
    pub(crate) padding_rows_num: usize,
    /// Challenges
    pub(crate) challenges: Challenges<Value<F>>,
}

impl RwTable {
    /// Prepad Rw::Start rows to target length
    pub fn assignments_prepad(&self, rows: &[Rw], padding_rows_num: usize) -> (Vec<Rw>, usize) {
        // Remove Start rows as we will add them from scratch.
        let rows: Vec<Rw> = rows
            .iter()
            .skip_while(|rw| matches!(rw, Rw::Start { .. }))
            .cloned()
            .collect();
        let padding_length = RwMap::padding_len(rows.len(), padding_rows_num);
        let padding = (1..=padding_length).map(|rw_counter| Rw::Start { rw_counter });
        (padding.chain(rows.into_iter()).collect(), padding_length)
    }

    pub(crate) fn load_with_region<F: Field>(
        &self,
        region: &mut Region<'_, F>,
        args: RwTableLoadArgs<F>,
    ) -> Result<(), Error> {
        if let Some(rws) = args.rws {
            let (rows, _) = self.assignments_prepad(rws, args.padding_rows_num);

            for (offset, row) in rows.iter().enumerate() {
                let row = &row.table_assignment(args.challenges.evm_word());
                self.assign_row(region, offset, row)?;
            }
        } else {
            log::error!("The args.rws in RwTable::load_with_region is None");
        }
        Ok(())
    }
}

impl<'a, F: Field> AssignTable<F> for RwTable {
    const TABLE_NAME: &'static str = "rw table";
    type TableRowValue = RwRow<Value<F>>;
    type LoadArgs = RwTableLoadArgs<'a, F>;
    type AssignmentsArgs = ();

    /// Construct a new RwTable
    fn construct<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            rw_counter: meta.advice_column(),
            is_write: meta.advice_column(),
            tag: meta.advice_column(),
            id: meta.advice_column(),
            address: meta.advice_column(),
            field_tag: meta.advice_column(),
            storage_key: meta.advice_column_in(SecondPhase),
            value: meta.advice_column_in(SecondPhase),
            value_prev: meta.advice_column_in(SecondPhase),
            // It seems that aux1 for the moment is not using randomness
            // TODO check in a future review
            aux1: meta.advice_column_in(SecondPhase),
            aux2: meta.advice_column_in(SecondPhase),
        }
    }

    fn assign_row<F: Field>(
        &self,
        region: &mut Region<F>,
        offset: usize,
        row: &Self::TableRowValue,
    ) -> Result<(), Error> {
        for (column, value) in [
            (self.rw_counter, row.rw_counter),
            (self.is_write, row.is_write),
            (self.tag, row.tag),
            (self.id, row.id),
            (self.address, row.address),
            (self.field_tag, row.field_tag),
            (self.storage_key, row.storage_key),
            (self.value, row.value),
            (self.value_prev, row.value_prev),
            (self.aux1, row.aux1),
            (self.aux2, row.aux2),
        ] {
            region.assign_advice(|| "assign rw row on rw table", column, offset, || value)?;
        }
        Ok(())
    }

    fn assignments<F: Field>(&self, args: Self::LoadArgs) -> Vec<Self::TableRowValue> {
        todo!()
    }

    /// Assign the `RwTable` from a `RwMap`, following the same
    /// table layout that the State Circuit uses.
    fn load(&self, layouter: &mut impl Layouter<F>, args: Self::LoadArgs) -> Result<(), Error> {
        layouter.assign_region(
            || format!("assign {}", Self::TABLE_NAME),
            |mut region| self.load_with_region(&mut region, args),
        )
    }
}

impl<F: Field> LookupTable<F> for RwTable {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![
            self.rw_counter.into(),
            self.is_write.into(),
            self.tag.into(),
            self.id.into(),
            self.address.into(),
            self.field_tag.into(),
            self.storage_key.into(),
            self.value.into(),
            self.value_prev.into(),
            self.aux1.into(),
            self.aux2.into(),
        ]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("rw_counter"),
            String::from("is_write"),
            String::from("tag"),
            String::from("id"),
            String::from("address"),
            String::from("field_tag"),
            String::from("storage_key"),
            String::from("value"),
            String::from("value_prev"),
            String::from("aux1"),
            String::from("aux2"),
        ]
    }
}
