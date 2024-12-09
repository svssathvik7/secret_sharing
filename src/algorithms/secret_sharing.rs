use num_bigint::BigInt;

pub trait SecretSharing {
    fn reconstruct(&self, shares: &Vec<(usize, BigInt)>) -> Result<BigInt, String>;
}