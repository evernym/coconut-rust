use failure::Error;

#[derive(Debug, Fail)]
pub enum CoconutError {
    #[fail(
        display = "Verkey valid for {} messages but given {} messages",
        expected, given
    )]
    UnsupportedNoOfMessages { expected: usize, given: usize },

    #[fail(
        display = "Same no of bases and exponents required. {} bases and {} exponents",
        bases, exponents
    )]
    UnequalNoOfBasesExponents { bases: usize, exponents: usize },

    #[fail(display = "Error with message {:?}", msg)]
    GeneralError { msg: String },
}
