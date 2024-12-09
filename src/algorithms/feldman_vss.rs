use num_bigint::BigInt;

use super::{secret_sharing::SecretSharing, shamir_secret_sharing::ShamirSecretSharing};

#[derive(Debug)]
pub struct FeldmanResponse{
    pub shares: Vec<(usize,BigInt)>,
    pub committments: Vec<BigInt>
}

pub struct FeldmanVSS{
    // feldmanvss is sss with ability to verify the shares through committments
    pub committments: Vec<BigInt>,
    generator: BigInt,
    shamir: ShamirSecretSharing
}

impl FeldmanVSS{
    pub fn new(threshold: usize, total_shares: usize, prime: Option<BigInt>) -> Result<Self,String>{
        if threshold > total_shares{
            return Err("Threshold has to be less than total shares!".to_string());
        }

        let prime = if let Some(p) = prime{
            p
        }else{
            BigInt::from(2147483647)
        };

        if prime <= BigInt::from(0){
            return Err("Prime should not less than 1".to_string());
        }

        // shamir object to perform sss operations
        let shamir = ShamirSecretSharing::new(threshold, total_shares, Some(prime)).unwrap();

        Ok(Self{
            generator: BigInt::from(2),
            committments: Vec::new(),
            shamir
        })
    }

    // generate Ci committments for verification of shares
    fn generate_committments(&mut self){
        let coefficients = &self.shamir.coefficients;
        let mut committments: Vec<BigInt> = Vec::new();
        for i in 0..coefficients.len(){
            // g^ai
            committments.push(self.generator.modpow(&coefficients[i],&self.shamir.prime));
        }
        self.committments = committments;
    }

    // call sss share generation logic
    pub fn generate_shares(&mut self, secret: BigInt) -> Result<FeldmanResponse, String> {
        let shares = self.shamir.generate_shares(secret.clone()).unwrap();
        self.generate_committments();
        let shares = FeldmanResponse{
            shares,
            committments:self.committments.clone()
        };
        Ok(shares)
    }

    // use committments to validate shares
    pub fn validate_shares(&self,share:(usize,BigInt)) -> bool{
        // share is in the form (i,v)
        let i = BigInt::from(share.0);
        let v = share.1;
        let lhs = self.generator.modpow(&v, &self.shamir.prime);
        let mut rhs = self.committments[0].clone();
        for it in 1..self.committments.len(){
            // i^j
            let exp_term = i.modpow(&BigInt::from(it),&self.shamir.prime);
            // Ci^(i^j)
            let term = self.committments[it].modpow(&BigInt::from(exp_term), &self.shamir.prime);
            rhs = (rhs*term) % &self.shamir.prime;
        }
        lhs == rhs
    }
}

impl SecretSharing for FeldmanVSS{
    fn reconstruct(&self, shares: &Vec<(usize, BigInt)>) -> Result<BigInt, String> {
        self.shamir.reconstruct(shares)
    }
}