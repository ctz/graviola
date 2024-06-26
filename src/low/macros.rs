/// takes a sequence of expressions (not separated by commas),
/// and feeds them into concat!() to form a single string
///
/// named after perl's q operator.
macro_rules! Q {
    ($($e:expr)*) => {
        concat!($($e ,)*)
    };
}

pub(crate) use Q;

/// Label macro, which just resolves to the id as a string,
/// but keeps the name close to it in the code.
///
/// See the warnings about labels in the rust guide, this
/// means we use local labels without compromising so much
/// on readability.
macro_rules! Label {
    // declaration form
    ($name:literal, $id:literal) => {
        stringify!($id)
    };

    // reference form (downwards)
    ($name:literal, $id:literal, After) => {
        stringify!($id f)
    };

    // reference form (upwards)
    ($name:literal, $id:literal, Before) => {
        stringify!($id b)
    }
}

pub(crate) use Label;
