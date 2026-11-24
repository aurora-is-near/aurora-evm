#[cfg(feature = "force-debug")]
macro_rules! trace_op {
	($($arg:tt)*) => (log::trace!(target: "evm", "OpCode {}", format_args!($($arg)*)));
}

#[cfg(not(feature = "force-debug"))]
macro_rules! trace_op {
    ($($arg:tt)*) => {};
}

macro_rules! try_or_fail {
    ( $e:expr ) => {
        match $e {
            Ok(v) => v,
            Err(e) => return Control::Exit(e.into()),
        }
    };
}

macro_rules! pop_h256 {
	( $machine:expr, $( $x:ident ),* ) => (
		$(
			let $x = match $machine.stack_mut().pop() {
				Ok(value) => H256(value.to_big_endian()),
				Err(e) => return Control::Exit(e.into()),
			};
		)*
	);
}

macro_rules! pop_u256 {
	( $machine:expr, $( $x:ident ),* ) => (
		$(
			let $x = match $machine.stack_mut().pop() {
				Ok(value) => value,
				Err(e) => return Control::Exit(e.into()),
			};
		)*
	);
}

macro_rules! push_h256 {
	( $machine:expr, $( $x:expr ),* ) => (
		$(
			match $machine.stack_mut().push(U256::from_big_endian(&$x[..])) {
				Ok(()) => (),
				Err(e) => return Control::Exit(e.into()),
			}
		)*
	)
}

macro_rules! push_u256 {
	( $machine:expr, $( $x:expr ),* ) => (
		$(
			match $machine.stack_mut().push($x) {
				Ok(()) => (),
				Err(e) => return Control::Exit(e.into()),
			}
		)*
	)
}

macro_rules! op1_u256_fn {
    ( $machine:expr, $op:path ) => {{
        $crate::macros::pop_u256!($machine, op1);
        let ret = $op(op1);
        $crate::macros::push_u256!($machine, ret);
        $crate::macros::trace_op!("{} {}: {}", stringify!($op), op1, ret);

        Control::Continue(1)
    }};
}

macro_rules! op2_u256_bool_ref {
    ( $machine:expr, $op:ident ) => {{
        use $crate::utils::{U256_ONE, U256_ZERO};

        $crate::macros::pop_u256!($machine, op1, op2);
        let ret = op1.$op(&op2);
        $crate::macros::push_u256!($machine, if ret { U256_ONE } else { U256_ZERO });
        $crate::macros::trace_op!("{} {}, {}: {}", stringify!($op), op1, op2, ret);

        Control::Continue(1)
    }};
}

macro_rules! op2_u256 {
    ( $machine:expr, $op:ident ) => {{
        $crate::macros::pop_u256!($machine, op1, op2);
        let ret = op1.$op(op2);
        $crate::macros::push_u256!($machine, ret);
        $crate::macros::trace_op!("{} {}, {}: {}", stringify!($op), op1, op2, ret);

        Control::Continue(1)
    }};
}

macro_rules! op2_u256_tuple {
    ( $machine:expr, $op:ident ) => {{
        $crate::macros::pop_u256!($machine, op1, op2);
        let (ret, ..) = op1.$op(op2);
        $crate::macros::push_u256!($machine, ret);
        $crate::macros::trace_op!("{} {}, {}: {}", stringify!($op), op1, op2, ret);

        Control::Continue(1)
    }};
}

macro_rules! op2_u256_fn {
    ( $machine:expr, $op:path ) => {{
        $crate::macros::pop_u256!($machine, op1, op2);
        let ret = $op(op1, op2);
        $crate::macros::push_u256!($machine, ret);
        $crate::macros::trace_op!("{} {}, {}: {}", stringify!($op), op1, op2, ret);

        Control::Continue(1)
    }};
}

macro_rules! op3_u256_fn {
    ( $machine:expr, $op:path ) => {{
        $crate::macros::pop_u256!($machine, op1, op2, op3);
        let ret = $op(op1, op2, op3);
        $crate::macros::push_u256!($machine, ret);
        $crate::macros::trace_op!("{} {}, {}, {}: {}", stringify!($op), op1, op2, op3, ret);

        Control::Continue(1)
    }};
}

macro_rules! as_usize_or_fail {
    ( $v:expr ) => {{
        if $v > $crate::utils::USIZE_MAX {
            return Control::Exit(ExitError::UsizeOverflow.into());
        }

        $v.as_usize()
    }};

    ( $v:expr, $reason:expr ) => {{
        if $v > $crate::utils::USIZE_MAX {
            return Control::Exit($reason.into());
        }

        $v.as_usize()
    }};
}

pub(crate) use {
    as_usize_or_fail, op1_u256_fn, op2_u256, op2_u256_bool_ref, op2_u256_fn, op2_u256_tuple,
    op3_u256_fn, pop_h256, pop_u256, push_h256, push_u256, trace_op, try_or_fail,
};
