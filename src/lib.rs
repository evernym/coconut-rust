#![allow(non_snake_case)]

#[cfg(all(feature = "G1G2", feature = "G2G1"))]
compile_error!("features `G1G2` and `G2G1` are mutually exclusive");

#[macro_use]
extern crate amcl_wrapper;

#[macro_use]
extern crate ps_sig;

use ps_sig::pok_vc;
use ps_sig::{ate_2_pairing, OtherGroup, OtherGroupVec, SignatureGroup, SignatureGroupVec};

extern crate rand;

#[macro_use]
extern crate failure;

extern crate serde;
#[macro_use]
extern crate serde_derive;

pub mod errors;
#[macro_use]
pub mod elgamal;
pub mod keygen;
pub mod pok_sig;
pub mod signature;
pub mod sss;
