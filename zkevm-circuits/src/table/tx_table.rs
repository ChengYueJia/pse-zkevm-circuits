use crate::evm_circuit::util::rlc;
use crate::impl_expr;
use crate::table::{AssignTable, LookupTable};
use crate::tx_circuit::sign_verify::AssignedSignatureVerify;
use crate::util::{random_linear_combine_word, Challenges};
use eth_types::geth_types::Transaction;
use eth_types::{Address, Field, ToLittleEndian, ToScalar};
use halo2_proofs::circuit::AssignedCell;
use halo2_proofs::{circuit::Layouter, plonk::*, poly::Rotation};
use halo2_proofs::{
    circuit::{Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error},
};
use strum_macros::{EnumCount, EnumIter};

/// Tag used to identify each field in the transaction in a row of the
/// transaction table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxFieldTag {
    /// Unused tag
    Null = 0,
    /// Nonce
    Nonce,
    /// Gas
    Gas,
    /// GasPrice
    GasPrice,
    /// CallerAddress
    CallerAddress,
    /// CalleeAddress
    CalleeAddress,
    /// IsCreate
    IsCreate,
    /// Value
    Value,
    /// CallDataLength
    CallDataLength,
    /// Gas cost for transaction call data (4 for byte == 0, 16 otherwise)
    CallDataGasCost,
    /// TxSignHash: Hash of the transaction without the signature, used for
    /// signing.
    TxSignHash,
    /// CallData
    CallData,
}
impl_expr!(TxFieldTag);

/// Alias for TxFieldTag used by EVM Circuit
pub type TxContextFieldTag = TxFieldTag;

/// Table that contains the fields of all Transactions in a block
#[derive(Clone, Debug)]
pub struct TxTable {
    /// Tx ID
    pub tx_id: Column<Advice>,
    /// Tag (TxContextFieldTag)
    pub tag: Column<Fixed>,
    /// Index for Tag = CallData
    pub index: Column<Advice>,
    /// Value
    pub value: Column<Advice>,
}

/// Table load arguments
pub(crate) struct TxTableLoadArgs<'txs, 'sigs, F: Field> {
    /// Txs Values. Used for load method
    pub(crate) txs: &'txs Vec<Transaction>,
    /// Max size of txs
    pub(crate) max_txs: usize,
    /// The sig data
    pub(crate) sig_verif_vec: Option<&'sigs Vec<AssignedSignatureVerify<F>>>,
    /// Challenges
    pub(crate) challenges: Challenges<Value<F>>,
}

/// Table load arguments
pub(crate) struct TxTableAssignmentsArgs<'tx, 'sig, F: Field> {
    /// Tx index.
    tx_id: u64,
    /// Tx Values. Used for load method.
    tx: &'tx Transaction,
    /// The signature verify.
    signature_verify: Option<&'sig AssignedSignatureVerify<F>>,
    /// Challenges
    challenges: Challenges<Value<F>>,
}

type TxTableRow<F> = (Value<F>, TxFieldTag, Value<F>, Value<F>);

impl TxTable {
    fn assign_row<F: Field>(
        &self,
        region: &mut Region<F>,
        offset: usize,
        row: TxTableRow<F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        region.assign_advice(
            || format!("assign tx_id{}", offset),
            self.tx_id,
            offset,
            || row.0,
        )?;
        region.assign_fixed(
            || format!("assign tag {}", offset),
            self.tag,
            offset,
            || Value::known(F::from(row.1 as u64)),
        )?;
        region.assign_advice(
            || format!("assign index{}", offset),
            self.index,
            offset,
            || row.2,
        )?;
        region.assign_advice(
            || format!("assign value{}", offset),
            self.value,
            offset,
            || row.3,
        )
    }
}

impl<'txs, 'sigs, 'tx, 'sig, F: Field> AssignTable<F> for TxTable {
    const TABLE_NAME: &'static str = "tx table";
    type TableRowValue = TxTableRow<F>;
    type LoadArgs = TxTableLoadArgs<'txs, 'sigs, F>;
    type AssignmentsArgs = TxTableAssignmentsArgs<'tx, 'sig, F>;

    /// Construct a new TxTable
    fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            tx_id: meta.advice_column(),
            tag: meta.fixed_column(),
            index: meta.advice_column(),
            value: meta.advice_column_in(SecondPhase),
        }
    }

    fn assignments<F: Field>(
        &self,
        Self::AssignmentsArgs {
            tx_id,
            tx,
            sig_verify,
            challenges,
        }: Self::AssignmentsArgs,
    ) -> Vec<Self::TableRowValue> {
        let rlc_fn = |value| {
            challenges
                .evm_word()
                .map(|challenge| rlc::value(&value, challenge))
        };

        [
            vec![
                (
                    Value::known(F::from(tx_id)),
                    TxContextFieldTag::Nonce,
                    Value::known(F::zero()),
                    rlc_fn(tx.nonce.to_le_bytes()),
                ),
                (
                    Value::known(F::from(tx_id)),
                    TxContextFieldTag::Gas,
                    Value::known(F::zero()),
                    Value::known(F::from(tx.gas_limit.as_u64())),
                ),
                (
                    Value::known(F::from(tx_id)),
                    TxContextFieldTag::GasPrice,
                    Value::known(F::zero()),
                    rlc_fn(tx.gas_price.to_le_bytes()),
                ),
                (
                    Value::known(F::from(tx_id)),
                    TxContextFieldTag::CallerAddress,
                    Value::known(F::zero()),
                    Value::known(tx.from.to_scalar().expect("tx.from too big")),
                ),
                (
                    Value::known(F::from(tx_id)),
                    TxContextFieldTag::CalleeAddress,
                    Value::known(F::zero()),
                    Value::known(
                        tx.to
                            .unwrap_or_else(Address::zero)
                            .to_scalar()
                            .expect("tx.to too big"),
                    ),
                ),
                (
                    Value::known(F::from(tx_id)),
                    TxContextFieldTag::IsCreate,
                    Value::known(F::zero()),
                    Value::known(F::from(tx.to.is_none() as u64)),
                ),
                (
                    Value::known(F::from(tx_id)),
                    TxContextFieldTag::Value,
                    Value::known(F::zero()),
                    rlc_fn(tx.value.to_le_bytes()),
                ),
                (
                    Value::known(F::from(tx_id)),
                    TxContextFieldTag::CallDataLength,
                    Value::known(F::zero()),
                    Value::known(F::from(tx.call_data.0.len() as u64)),
                ),
                (
                    Value::known(F::from(tx_id)),
                    TxContextFieldTag::CallDataGasCost,
                    Value::known(F::zero()),
                    Value::known(F::from(
                        tx.call_data
                            .0
                            .iter()
                            .fold(0, |acc, byte| acc + if *byte == 0 { 4 } else { 16 }),
                    )),
                ),
                (
                    Value::known(F::from(tx_id)),
                    TxContextFieldTag::TxSignHash,
                    Value::known(F::zero()),
                    // Value::known(F::from(tx.call_data_length as u64)),
                    if let Some(sig) = sig_verify {
                        sig.msg_hash_rlc.value().copied()
                    } else {
                        Value::known(F::zero())
                    },
                ),
            ],
            // Assignment call data
            tx.call_data
                .0
                .iter()
                .enumerate()
                .map(|(idx, byte)| {
                    (
                        Value::known(F::from(tx_id)),
                        TxContextFieldTag::CallData,
                        Value::known(F::from(idx as u64)),
                        Value::known(F::from(*byte as u64)),
                    )
                })
                .collect(),
        ]
        .concat()
    }

    /// Assign the `TxTable` from a list of block `Transaction`s, followig the
    /// same layout that the Tx Circuit uses.
    fn load(&self, layouter: &mut impl Layouter<F>, args: Self::LoadArgs) -> Result<(), Error> {
        assert!(
            args.txs.len() <= args.max_txs,
            "txs.len() <= max_txs: txs.len()={}, max_txs={}",
            args.txs.len(),
            args.max_txs
        );

        layouter.assign_region(
            || format!("assign {}", Self::TABLE_NAME),
            |mut region| {
                let mut offset: usize = 0;

                // Empty row
                self.assign_row(
                    &mut region,
                    offset,
                    (
                        Value::known(F::zero()),
                        TxFieldTag::Null,
                        Value::known(F::zero()),
                        Value::known(F::zero()),
                    ),
                )?;

                offset += 1;

                let padding_txs: Vec<Transaction> = (args.txs.len()..args.max_txs)
                    .map(|_i| Transaction::default())
                    .collect();
                for (i, tx) in args.txs.iter().chain(padding_txs.iter()).enumerate() {
                    let sig_verify = if let Some(sig_vec) = args.sig_verif_vec {
                        sig_vec.get(i)
                    } else {
                        None
                    };

                    let tx_id = i + 1;
                    for row in self.assignments(Self::AssignmentsArgs {
                        tx_id: tx_id.try_into().unwrap(),
                        tx,
                        sig_verify,
                        challenges: args.challenges,
                    }) {
                        let assigned_cell = self.assign_row(&mut region, offset, row).unwrap();

                        if let Some(sig) = sig_verify {
                            // Ref. spec 0. Copy constraints using fixed offsets between the tx
                            // rows and the SignVerifyChip
                            match row.1 {
                                TxContextFieldTag::CallerAddress => region
                                    .constrain_equal(assigned_cell.cell(), sig.address.cell())?,
                                TxContextFieldTag::TxSignHash => region.constrain_equal(
                                    assigned_cell.cell(),
                                    sig.msg_hash_rlc.cell(),
                                )?,
                                _ => (),
                            }
                        }

                        offset += 1;
                    }
                }
                Ok(())
            },
        )
    }
}

impl<F: Field> LookupTable<F> for TxTable {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![
            self.tx_id.into(),
            self.tag.into(),
            self.index.into(),
            self.value.into(),
        ]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("tx_id"),
            String::from("tag"),
            String::from("index"),
            String::from("value"),
        ]
    }

    fn table_exprs(&self, meta: &mut VirtualCells<F>) -> Vec<Expression<F>> {
        vec![
            meta.query_advice(self.tx_id, Rotation::cur()),
            meta.query_fixed(self.tag, Rotation::cur()),
            meta.query_advice(self.index, Rotation::cur()),
            meta.query_advice(self.value, Rotation::cur()),
        ]
    }
}
