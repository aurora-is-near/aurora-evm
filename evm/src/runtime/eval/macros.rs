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
			let $x = match $machine.machine.stack_mut().pop() {
				Ok(value) => H256(value.to_big_endian()),
				Err(e) => return Control::Exit(e.into()),
			};
		)*
	);
}

macro_rules! pop_u256 {
	( $machine:expr, $( $x:ident ),* ) => (
		$(
			let $x = match $machine.machine.stack_mut().pop() {
				Ok(value) => value,
				Err(e) => return Control::Exit(e.into()),
			};
		)*
	);
}

macro_rules! push_h256 {
	( $machine:expr, $( $x:expr ),* ) => (
		$(
			match $machine.machine.stack_mut().push(U256::from_big_endian(&$x[..])) {
				Ok(()) => (),
				Err(e) => return Control::Exit(e.into()),
			}
		)*
	)
}

macro_rules! push_u256 {
	( $machine:expr, $( $x:expr ),* ) => (
		$(
			match $machine.machine.stack_mut().push($x) {
				Ok(()) => (),
				Err(e) => return Control::Exit(e.into()),
			}
		)*
	)
}

macro_rules! as_usize_or_fail {
    ( $v:expr ) => {{
        if $v > crate::utils::USIZE_MAX {
            return Control::Exit(ExitError::UsizeOverflow.into());
        }

        $v.as_usize()
    }};

    ( $v:expr, $reason:expr ) => {{
        if $v > crate::utils::USIZE_MAX {
            return Control::Exit($reason.into());
        }

        $v.as_usize()
    }};
}
