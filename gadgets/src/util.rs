//! Utility traits, functions used in the crate.
use eth_types::{
    evm_types::{GasCost, OpcodeId},
    U256,
};
use halo2_proofs::{arithmetic::FieldExt, plonk::Expression};

/// Returns the sum of the passed in cells
pub mod sum {
    use crate::util::Expr;
    use halo2_proofs::{arithmetic::FieldExt, plonk::Expression};

    /// Returns an expression for the sum of the list of expressions.
    pub fn expr<F: FieldExt, E: Expr<F>, I: IntoIterator<Item = E>>(inputs: I) -> Expression<F> {
        inputs
            .into_iter()
            .fold(0.expr(), |acc, input| acc + input.expr())
    }

    /// Returns the sum of the given list of values within the field.
    pub fn value<F: FieldExt>(values: &[u8]) -> F {
        values
            .iter()
            .fold(F::zero(), |acc, value| acc + F::from(*value as u64))
    }
}

/// Returns `1` when `expr[0] && expr[1] && ... == 1`, and returns `0`
/// otherwise. Inputs need to be boolean
pub mod and {
    use crate::util::Expr;
    use halo2_proofs::{arithmetic::FieldExt, plonk::Expression};

    /// Returns an expression that evaluates to 1 only if all the expressions in
    /// the given list are 1, else returns 0.
    pub fn expr<F: FieldExt, E: Expr<F>, I: IntoIterator<Item = E>>(inputs: I) -> Expression<F> {
        inputs
            .into_iter()
            .fold(1.expr(), |acc, input| acc * input.expr())
    }

    /// Returns the product of all given values.
    pub fn value<F: FieldExt>(inputs: Vec<F>) -> F {
        inputs.iter().fold(F::one(), |acc, input| acc * input)
    }
}

/// Returns `1` when `expr[0] || expr[1] || ... == 1`, and returns `0`
/// otherwise. Inputs need to be boolean
pub mod or {
    use super::{and, not};
    use crate::util::Expr;
    use halo2_proofs::{arithmetic::FieldExt, plonk::Expression};

    /// Returns an expression that evaluates to 1 if any expression in the given
    /// list is 1. Returns 0 if all the expressions were 0.
    pub fn expr<F: FieldExt, E: Expr<F>, I: IntoIterator<Item = E>>(inputs: I) -> Expression<F> {
        not::expr(and::expr(inputs.into_iter().map(not::expr)))
    }

    /// Returns the value after passing all given values through the OR gate.
    pub fn value<F: FieldExt>(inputs: Vec<F>) -> F {
        not::value(and::value(inputs.into_iter().map(not::value).collect()))
    }
}

/// Returns `1` when `b == 0`, and returns `0` otherwise.
/// `b` needs to be boolean
pub mod not {
    use crate::util::Expr;
    use halo2_proofs::{arithmetic::FieldExt, plonk::Expression};

    /// Returns an expression that represents the NOT of the given expression.
    pub fn expr<F: FieldExt, E: Expr<F>>(b: E) -> Expression<F> {
        1.expr() - b.expr()
    }

    /// Returns a value that represents the NOT of the given value.
    pub fn value<F: FieldExt>(b: F) -> F {
        F::one() - b
    }
}

/// Returns `a ^ b`.
/// `a` and `b` needs to be boolean
pub mod xor {
    use crate::util::Expr;
    use halo2_proofs::{arithmetic::FieldExt, plonk::Expression};

    /// Returns an expression that represents the XOR of the given expression.
    pub fn expr<F: FieldExt, E: Expr<F>>(a: E, b: E) -> Expression<F> {
        a.expr() + b.expr() - 2.expr() * a.expr() * b.expr()
    }

    /// Returns a value that represents the XOR of the given value.
    pub fn value<F: FieldExt>(a: F, b: F) -> F {
        a + b - F::from(2u64) * a * b
    }
}

/// Returns `when_true` when `selector == 1`, and returns `when_false` when
/// `selector == 0`. `selector` needs to be boolean.
pub mod select {
    use crate::util::Expr;
    use halo2_proofs::{arithmetic::FieldExt, plonk::Expression};

    /// Returns the `when_true` expression when the selector is true, else
    /// returns the `when_false` expression.
    pub fn expr<F: FieldExt>(
        selector: Expression<F>,
        when_true: Expression<F>,
        when_false: Expression<F>,
    ) -> Expression<F> {
        selector.clone() * when_true + (1.expr() - selector) * when_false
    }

    /// Returns the `when_true` value when the selector is true, else returns
    /// the `when_false` value.
    pub fn value<F: FieldExt>(selector: F, when_true: F, when_false: F) -> F {
        selector * when_true + (F::one() - selector) * when_false
    }

    /// Returns the `when_true` word when selector is true, else returns the
    /// `when_false` word.
    pub fn value_word<F: FieldExt>(
        selector: F,
        when_true: [u8; 32],
        when_false: [u8; 32],
    ) -> [u8; 32] {
        if selector == F::one() {
            when_true
        } else {
            when_false
        }
    }
}

/// Trait that implements functionality to get a constant expression from
/// commonly used types.
pub trait Expr<F: FieldExt> {
    /// Returns an expression for the type.
    fn expr(&self) -> Expression<F>;
}

/// Implementation trait `Expr` for type able to be casted to u64
#[macro_export]
macro_rules! impl_expr {
    ($type:ty) => {
        impl<F: halo2_proofs::arithmetic::FieldExt> $crate::util::Expr<F> for $type {
            #[inline]
            fn expr(&self) -> Expression<F> {
                Expression::Constant(F::from(*self as u64))
            }
        }
    };
    ($type:ty, $method:path) => {
        impl<F: halo2_proofs::arithmetic::FieldExt> $crate::util::Expr<F> for $type {
            #[inline]
            fn expr(&self) -> Expression<F> {
                Expression::Constant(F::from($method(self) as u64))
            }
        }
    };
}

impl_expr!(bool);
impl_expr!(u8);
impl_expr!(u64);
impl_expr!(usize);
impl_expr!(OpcodeId, OpcodeId::as_u8);
impl_expr!(GasCost, GasCost::as_u64);

impl<F: FieldExt> Expr<F> for Expression<F> {
    #[inline]
    fn expr(&self) -> Expression<F> {
        self.clone()
    }
}

impl<F: FieldExt> Expr<F> for &Expression<F> {
    #[inline]
    fn expr(&self) -> Expression<F> {
        (*self).clone()
    }
}

impl<F: FieldExt> Expr<F> for i32 {
    #[inline]
    fn expr(&self) -> Expression<F> {
        Expression::Constant(
            F::from(self.unsigned_abs() as u64)
                * if self.is_negative() {
                    -F::one()
                } else {
                    F::one()
                },
        )
    }
}

/// Given a bytes-representation of an expression, it computes and returns the
/// single expression.
pub fn expr_from_bytes<F: FieldExt, E: Expr<F>>(bytes: &[E]) -> Expression<F> {
    let mut value = 0.expr();
    let mut multiplier = F::one();
    for byte in bytes.iter() {
        value = value + byte.expr() * multiplier;
        multiplier *= F::from(256);
    }
    value
}

/// Returns 2**by as FieldExt
pub fn pow_of_two<F: FieldExt>(by: usize) -> F {
    F::from(2).pow(&[by as u64, 0, 0, 0])
}

/// Returns tuple consists of low and high part of U256
pub fn split_u256(value: &U256) -> (U256, U256) {
    (
        U256([value.0[0], value.0[1], 0, 0]),
        U256([value.0[2], value.0[3], 0, 0]),
    )
}

/// Split a U256 value into 4 64-bit limbs stored in U256 values.
pub fn split_u256_limb64(value: &U256) -> [U256; 4] {
    [
        U256([value.0[0], 0, 0, 0]),
        U256([value.0[1], 0, 0, 0]),
        U256([value.0[2], 0, 0, 0]),
        U256([value.0[3], 0, 0, 0]),
    ]
}

#[cfg(test)]
mod bool_logic_macro_test {

    // bool!((selectorA && !selectorB) || selectorC)
    // or::expr([and::expr([selectorA.expr(), not::expr(selectorB.expr())]),
    // selectorC.expr()])
    #[derive(Debug, Default, PartialEq)]
    struct Not<T>(T);

    #[derive(Debug, PartialEq)]
    struct And<L, R>(L, R);

    #[derive(Debug, PartialEq)]
    struct Or<L, R>(L, R);
    // match order is quite important
    macro_rules! bool {
        // and(not)
        // !a && !b
        (!$a:tt && !$b:tt) => {{
            let left = bool!(!$a);
            let right = bool!(!$b);
            let res = And(left, right);
            println!("and-not-ab1--{:?}", res);
            res
        }};
        ((!$a:tt && !$b:tt)) => {{
            let left = bool!(!$a);
            let right = bool!(!$b);
            let res = And(left, right);
            println!("and-not-ab1()--{:?}", res);
            res
        }};
        // (!a) && (!b)
        ((!$a:tt) && (!$b:tt)) => {{
            let left = bool!(!$a);
            let right = bool!(!$b);
            let res = And(left, right);
            println!("and-not-ab2--{:?}", res);
            res
        }};
        (((!$a:tt) && (!$b:tt))) => {{
            let left = bool!(!$a);
            let right = bool!(!$b);
            let res = And(left, right);
            println!("and-not-ab2()--{:?}", res);
            res
        }};
        // a && !b, a && !(b)
        ($a:tt && !$b:tt) => {{
            let left = bool!($a);
            let right = bool!(!$b);
            let res = And(left, right);
            println!("and-not-b1--{:?}", res);
            res
        }};
        (($a:tt && !$b:tt)) => {{
            let left = bool!($a);
            let right = bool!(!$b);
            let res = And(left, right);
            println!("and-not-b1()--{:?}", res);
            res
        }};
        // a && (!b)
        ($a:tt && (!$b:tt)) => {{
            let left = bool!($a);
            let right = bool!(!$b);
            let res = And(left, right);
            println!("and-not-b2--{:?}", res);
            res
        }};
        (($a:tt && (!$b:tt))) => {{
            let left = bool!($a);
            let right = bool!(!$b);
            let res = And(left, right);
            println!("and-not-b2()--{:?}", res);
            res
        }};
        // !a && b , !(a) && b
        (!$a:tt && $b:tt) => {{
            let left = bool!(!$a);
            let right = bool!($b);
            let res = And(left, right);
            println!("and-not-a1--{:?}", res);
            res
        }};
        ((!$a:tt && $b:tt)) => {{
            let left = bool!(!$a);
            let right = bool!($b);
            let res = And(left, right);
            println!("and-not-a1()--{:?}", res);
            res
        }};
        // (!a) && b
        ((!$a:tt) && $b:tt) => {{
            let left = bool!(!$a);
            let right = bool!($b);
            let res = And(left, right);
            println!("and-not-a2--{:?}", res);
            res
        }};
        (((!$a:tt) && $b:tt)) => {{
            let left = bool!(!$a);
            let right = bool!($b);
            let res = And(left, right);
            println!("and-not-a2()--{:?}", res);
            res
        }};

        // or(not)
        // !a && !b
        (!$a:tt || !$b:tt) => {{
            let left = bool!(!$a);
            let right = bool!(!$b);
            let res = Or(left, right);
            println!("or-not-ab1--{:?}", res);
            res
        }};
        ((!$a:tt || !$b:tt)) => {{
            let left = bool!(!$a);
            let right = bool!(!$b);
            let res = Or(left, right);
            println!("or-not-ab1()--{:?}", res);
            res
        }};
        // (!a) || (!b)
        ((!$a:tt) || (!$b:tt)) => {{
            let left = bool!(!$a);
            let right = bool!(!$b);
            let res = Or(left, right);
            println!("or-not-ab2--{:?}", res);
            res
        }};
        (((!$a:tt) || (!$b:tt))) => {{
            let left = bool!(!$a);
            let right = bool!(!$b);
            let res = Or(left, right);
            println!("or-not-ab2()--{:?}", res);
            res
        }};
        // a || !b, a || !(b)
        ($a:tt || !$b:tt) => {{
            let left = bool!($a);
            let right = bool!(!$b);
            let res = Or(left, right);
            println!("or-not-b1--{:?}", res);
            res
        }};
        (($a:tt || !$b:tt)) => {{
            let left = bool!($a);
            let right = bool!(!$b);
            let res = Or(left, right);
            println!("or-not-b1()--{:?}", res);
            res
        }};
        // a || (!b)
        ($a:tt || (!$b:tt)) => {{
            let left = bool!($a);
            let right = bool!(!$b);
            let res = Or(left, right);
            println!("or-not-b2--{:?}", res);
            res
        }};
        (($a:tt || (!$b:tt))) => {{
            let left = bool!($a);
            let right = bool!(!$b);
            let res = Or(left, right);
            println!("or-not-b2()--{:?}", res);
            res
        }};
        // !a || b , !(a) || b
        (!$a:tt || $b:tt) => {{
            let left = bool!(!$a);
            let right = bool!($b);
            let res = Or(left, right);
            println!("or-not-a1--{:?}", res);
            res
        }};
        ((!$a:tt || $b:tt)) => {{
            let left = bool!(!$a);
            let right = bool!($b);
            let res = Or(left, right);
            println!("or-not-a1()--{:?}", res);
            res
        }};
        // (!a) || b
        ((!$a:tt) || $b:tt) => {{
            let left = bool!(!$a);
            let right = bool!($b);
            let res = Or(left, right);
            println!("or-not-a2--{:?}", res);
            res
        }};
        (((!$a:tt) || $b:tt)) => {{
            let left = bool!(!$a);
            let right = bool!($b);
            let res = Or(left, right);
            println!("or-not-a2()--{:?}", res);
            res
        }};

        // not
        (!$a:tt) => {{
            let a = bool!($a);
            let res = Not(a);
            println!("not--{:?}", res);
            res
        }};
        (!($a:tt)) => {{
            let a = bool!($a);
            let res = Not(a);
            println!("not()--{:?}", res);
            res
        }};
        ((!$a:tt)) => {{
            let a = bool!($a);
            let res = Not(a);
            println!("(not)--{:?}", Not($a));
            res
        }};

        // and
        ($a:tt && $b:tt) => {{
            let left = bool!($a);
            let right = bool!($b);
            let res = And(left, right);
            println!("and1--{:?}", res);
            res
        }};
        (($a:tt && $b:tt)) => {{
            let left = bool!($a);
            let right = bool!($b);
            let res = And(left, right);
            println!("and2--{:?}", res);
            res
        }};

        // or
        ($a:tt || $b:tt) => {{
            let left = bool!($a);
            let right = bool!($b);
            let res = Or(left, right);
            println!("or-1--{:?}", res);
            res
        }};
        (($a:tt || $b:tt)) => {{
            let left = bool!($a);
            let right = bool!($b);
            let res = Or(left, right);
            println!("or-2--{:?}", res);
            res
        }};

        // nothing else type
        ($param:tt) => {{
            println!(" logic param: {}", $param);
            $param
        }};
    }

    #[test]
    fn tt_test_and_or_not() {
        let a = true;
        let b = false;
        let c = false;

        assert_eq!(bool!((a && !b) || c), Or(And(true, Not(false)), false));
        assert_eq!(bool!((a && c) || b), Or(And(true, false), false));
        assert_eq!(bool!(a || (a && b)), Or(true, And(true, false)));
        assert_eq!(bool!((a || c) && b), And(Or(true, false), false));
        assert_eq!(bool!(a && (a || b)), And(true, Or(true, false)));
        assert_eq!(
            bool!((a && b) || (a && b)),
            Or(And(true, false), And(true, false))
        );
        assert_eq!(
            bool!((a && b) || (a || b)),
            Or(And(true, false), Or(true, false))
        );
        assert_eq!(
            bool!((a && b) && (a || b)),
            And(And(true, false), Or(true, false))
        );
        assert_eq!(
            bool!((a || b) && (a || b)),
            And(Or(true, false), Or(true, false))
        );
    }

  #[test]
    fn tt_test_and_or() {
        let a = true;
        let b = false;
        let c = false;

        assert_eq!(bool!((!a && c) || b), Or(And(Not(true), false), false));
        assert_eq!(bool!((a && !c) || b), Or(And(true, Not(false)), false));
        assert_eq!(bool!((a && c) || !b), Or(And(true, false), Not(false)));


        assert_eq!(bool!(!a || (a && b)), Or(Not(true), And(true, false)));
        assert_eq!(bool!(a || (!a && b)), Or(true, And(Not(true), false)));
        assert_eq!(bool!(a || (a && !b)), Or(true, And(true, Not(false))));


        assert_eq!(bool!((!a || c) && b), And(Or(Not(true), false), false));
        assert_eq!(bool!((a || !c) && b), And(Or(true, Not(false)), false));
        assert_eq!(bool!((a || c) && !b), And(Or(true, false), Not(false)));

        assert_eq!(bool!(!a && (a || b)), And(Not(true), Or(true, false)));
        assert_eq!(bool!(a && (!a || b)), And(true, Or(Not(true), false)));
        assert_eq!(bool!(a && (a || !b)), And(true, Or(true, Not(false))));

        assert_eq!(
            bool!((!a && b) || (a && b)),
            Or(And(Not(true), false), And(true, false))
        );
        assert_eq!(
            bool!(!(a && b) || (a && b)),
            Or(Not(And(true, false)), And(true, false))
        );
        assert_eq!(
            bool!(!(!a && b) || !(a && b)),
            Or(Not(And(Not(true), false)), Not(And(true, false)))
        );


        assert_eq!(
            bool!((a && !b) || !(a || b)),
            Or(And(true, Not(false)), Not(Or(true, false)))
        );
        assert_eq!(
            bool!(!(!a && !b) || (!a || !b)),
            Or(Not(And(Not(true), Not(false))), Or(Not(true), Not(false)))
        );
        assert_eq!(
            bool!(!((a && b) || (a || b))),
           Not( Or(And(true, false), Or(true, false)))
        );


        assert_eq!(
            bool!((a || b) && (a || b)),
            And(Or(true, false), Or(true, false))
        );
    }

    #[test]
    fn tt_test_and_not() {
        let a = true;
        let b = false;
        let c = false;

        // a && !b
        assert_eq!(bool!(a && !b), And(true, Not(false))); // 1
        assert_eq!(bool!((a) && (!b)), And(true, Not(false))); // 1
        assert_eq!(bool!((a) && !(b)), And(true, Not(false))); // 2

        // !a && b
        assert_eq!(bool!(!(a) && b), And(Not(true), false)); // 1
        assert_eq!(bool!(!a && b), And(Not(true), false)); // 1
        assert_eq!(bool!((!a) && b), And(Not(true), false)); // 2

        // !a && !b -- and-not-ab2
        assert_eq!(bool!(!a && !b), And(Not(true), Not(false))); // 1
        assert_eq!(bool!((!a) && (!b)), And(Not(true), Not(false))); // 2

        // Not(blabla)
        assert_eq!(bool!(!(a && b)), Not(And(true, false)));
        assert_eq!(
            bool!(!(a && c) && b),
            And(Not(And(true, false)), false)
        );
        assert_eq!(
            bool!(!((a && c) && b)),
            Not(And(And(true, false), false))
        );
        assert_eq!(
            bool!(!(a && (a && b))),
            Not(And(true, And(true, false)))
        );
        assert_eq!(
            bool!(!((a && b) && (a && b))),
            Not(And(And(true, false), And(true, false)))
        );
    }

    #[test]
    fn tt_test_or_not() {
        let a = true;
        let b = false;
        let c = false;

        // a || !b
        assert_eq!(bool!(a || !b), Or(true, Not(false))); // 1
        assert_eq!(bool!((a) || (!b)), Or(true, Not(false))); // 1
        assert_eq!(bool!((a) || !(b)), Or(true, Not(false))); // 2

        // !a || b
        assert_eq!(bool!(!(a) || b), Or(Not(true), false)); // 1
        assert_eq!(bool!(!a || b), Or(Not(true), false)); // 1
        assert_eq!(bool!((!a) || b), Or(Not(true), false)); // 2

        // !a || !b -- Or-not-ab2
        assert_eq!(bool!(!a || !b), Or(Not(true), Not(false))); // 1
        assert_eq!(bool!((!a) || (!b)), Or(Not(true), Not(false))); // 2

        // Not(blabla)
        assert_eq!(bool!(!(a || b)), Not(Or(true, false)));
        assert_eq!(
            bool!(!(a || c) || b),
            Or(Not(Or(true, false)), false)
        );
        assert_eq!(
            bool!(!((a || c) || b)),
            Not(Or(Or(true, false), false))
        );
        assert_eq!(
            bool!(!(a || (a || b))),
            Not(Or(true, Or(true, false)))
        );
        assert_eq!(
            bool!(!((a || b) || (a || b))),
            Not(Or(Or(true, false), Or(true, false)))
        );
    }

    #[test]
    fn tt_test_and() {
        let a = false;
        let b = false;
        let c = true;

        assert_eq!(bool!(a && b), And(false, false));
        assert_eq!(bool!((a) && (b)), And(false, false));
        assert_eq!(bool!((a) && b), And(false, false));
        assert_eq!(bool!((a && b) && b), And(And(false, false), false));
        assert_eq!(
            bool!((a && b) && (b && c)),
            And(And(false, false), And(false, true))
        );
        assert_eq!(bool!((a && b)), And(false, false));
    }

    #[test]
    fn tt_test_or() {
        let a = false;
        let b = false;
        let c = true;

        assert_eq!(bool!(a || b), Or(false, false));
        assert_eq!(bool!((a) || (b)), Or(false, false));
        assert_eq!(bool!((a) || b), Or(false, false));
        assert_eq!(bool!((a || b) || b), Or(Or(false, false), false));
        assert_eq!(
            bool!((a || b) || (b || c)),
            Or(Or(false, false), Or(false, true))
        );
        assert_eq!(bool!((a || b)), Or(false, false));
    }

    #[test]
    fn tt_test_not() {
        let a = true;
        let b = false;
        let c = false;

        assert_eq!(bool!(!a), Not(true));
        assert_eq!(bool!((!a)), Not(true));
        assert_eq!(bool!(!(a)), Not(true));
    }

    #[test]
    fn tt_test_param() {
        let a = true;
        let b = false;
        let c = false;

        assert_eq!(bool!(a), true);
        assert_eq!(bool!((a)), true);
    }
}