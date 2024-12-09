use std::thread;

use num_bigint::BigInt;

use super::shamir_secret_sharing::ShamirSecretSharing;

#[derive(Debug)]
pub struct FeldmanResponse {
    pub shares: Vec<(usize, BigInt)>,
    pub committments: Vec<BigInt>,
}

pub struct FeldmanVSS {
    // feldmanvss is sss with ability to verify the shares through committments
    pub committments: Vec<BigInt>,
    generator: BigInt,
    shamir: ShamirSecretSharing,
}

impl FeldmanVSS {
    pub fn new(
        threshold: usize,
        total_shares: usize,
        prime: Option<BigInt>,
    ) -> Result<Self, String> {
        if threshold > total_shares {
            return Err("Threshold has to be less than total shares!".to_string());
        }

        let prime = if let Some(p) = prime {
            p
        } else {
            BigInt::from(2147483647)
        };

        if prime <= BigInt::from(0) {
            return Err("Prime should not less than 1".to_string());
        }

        // shamir object to perform sss operations
        let shamir = ShamirSecretSharing::new(threshold, total_shares, Some(prime)).unwrap();

        Ok(Self {
            generator: BigInt::from(2),
            committments: Vec::new(),
            shamir,
        })
    }

    // generate Ci committments for verification of shares
    fn generate_committments(&mut self) {
        let coefficients = &self.shamir.coefficients;
        let mut handles = vec![];
        for i in 0..coefficients.len() {
            // parallelizing - efficient for larger thresholds
            let generator = self.generator.clone();
            let coefficient = coefficients[i].clone();
            let prime = self.shamir.prime.clone();
            // g^ai
            handles.push(thread::spawn(move || {
                generator.modpow(&coefficient, &prime)
            }));
        }

        let mut committments = Vec::new();
        for handle in handles {
            let commitment = handle.join().unwrap();
            committments.push(commitment);
        }
        self.committments = committments;
    }

    // call sss share generation logic
    pub fn generate_shares(&mut self, secret: BigInt) -> Result<FeldmanResponse, String> {
        let shares = self.shamir.generate_shares(secret.clone()).unwrap();
        self.generate_committments();
        let shares = FeldmanResponse {
            shares,
            committments: self.committments.clone(),
        };
        Ok(shares)
    }

    // use committments to validate shares
    pub fn validate_shares(&self, share: (usize, BigInt)) -> bool {
        // share is in the form (i,v)
        let i = BigInt::from(share.0);
        let v = share.1;
        let lhs = self.generator.modpow(&v, &self.shamir.prime);
        let mut rhs = self.committments[0].clone();
        for it in 1..self.committments.len() {
            // i^j
            let exp_term = i.modpow(&BigInt::from(it), &self.shamir.prime);
            // Ci^(i^j)
            let term = self.committments[it].modpow(&BigInt::from(exp_term), &self.shamir.prime);
            rhs = (rhs * term) % &self.shamir.prime;
        }
        lhs == rhs
    }
    pub fn reconstruct(&self, shares: &Vec<(usize, BigInt)>) -> Result<BigInt, String> {
        self.shamir.reconstruct(shares)
    }
}

#[cfg(test)]
mod tests {
    use crate::algorithms::feldman_vss::FeldmanVSS;
    use num_bigint::BigInt;

    fn create_feldman_vss(threshold: usize, total_shares: usize) -> FeldmanVSS {
        let prime = BigInt::from(2147483647); // Prime number
        FeldmanVSS::new(threshold, total_shares, Some(prime)).unwrap()
    }

    #[test]
    fn test_invalid_threshold() {
        let threshold = 6; // Threshold larger than total_shares
        let total_shares = 5;
        let prime = BigInt::from(2147483647); // default Prime number

        let result = FeldmanVSS::new(threshold, total_shares, Some(prime));
        // Expecting an error because threshold is larger than total_shares
        assert!(
            result.is_err(),
            "Expected an error due to threshold being larger than total shares"
        );
    }

    #[test]
    fn test_generate_shares() {
        let threshold = 3;
        let total_shares = 5;
        let secret = BigInt::from(1234);
        let mut vss = create_feldman_vss(threshold, total_shares);

        let response = vss.generate_shares(secret.clone()).unwrap();

        // Check that the number of shares matches the total shares requested
        assert_eq!(
            response.shares.len(),
            total_shares,
            "Number of shares should match total_shares"
        );

        // Check that the number of commitments matches the threshold
        assert_eq!(
            response.committments.len(),
            threshold,
            "Number of commitments should match threshold"
        );

        // Ensure the commitments are non-empty
        assert!(
            !response.committments.is_empty(),
            "Commitments should not be empty"
        );
    }

    #[test]
    fn test_validate_shares_valid() {
        let threshold = 3;
        let total_shares = 5;
        let secret = BigInt::from(1234);
        let mut vss = create_feldman_vss(threshold, total_shares);
        let response = vss.generate_shares(secret.clone()).unwrap();
        let share = response.shares[0].clone();

        // Validate the first share
        let is_valid = vss.validate_shares(share);
        assert!(is_valid, "The share should be valid");
    }

    #[test]
    fn test_validate_shares_invalid() {
        let threshold = 3;
        let total_shares = 5;
        let secret = BigInt::from(1234);
        let mut vss = create_feldman_vss(threshold, total_shares);
        let response = vss.generate_shares(secret.clone()).unwrap();

        // Create an invalid share by modifying the value
        let mut invalid_share = response.shares[0].clone();
        invalid_share.1 += 1; // Invalid modification to the share value

        // Validate the invalid share
        let is_valid = vss.validate_shares(invalid_share);
        assert!(!is_valid, "The modified share should be invalid");
    }

    #[test]
    fn test_reconstruct_secret() {
        let threshold = 3;
        let total_shares = 5;
        let secret = BigInt::from(1234);
        let mut vss = create_feldman_vss(threshold, total_shares);
        let response = vss.generate_shares(secret.clone()).unwrap();

        // Reconstruct the secret using the first `threshold` number of shares
        let reconstructed_secret = vss
            .reconstruct(&response.shares[0..threshold].to_vec())
            .unwrap();

        // Ensure the reconstructed secret matches the original secret
        assert_eq!(
            reconstructed_secret, secret,
            "Reconstructed secret should match the original secret"
        );
    }

    #[test]
    fn test_threshold_equals_shares() {
        let threshold = 5;
        let total_shares = 5;
        let secret = BigInt::from(1234);
        let mut vss = create_feldman_vss(threshold, total_shares);

        // Generate shares and validate that they are valid
        let response = vss.generate_shares(secret.clone()).unwrap();
        for share in response.shares {
            assert!(
                vss.validate_shares(share),
                "All shares should be valid when threshold equals total shares"
            );
        }
    }

    #[test]
    fn test_edge_case_single_share() {
        let threshold = 1;
        let total_shares = 1;
        let secret = BigInt::from(1234);
        let mut vss = create_feldman_vss(threshold, total_shares);

        // Generate shares and validate that the single share is valid
        let response = vss.generate_shares(secret.clone()).unwrap();
        assert_eq!(
            response.shares.len(),
            total_shares,
            "Only one share should be generated"
        );

        let share = response.shares[0].clone();
        assert!(
            vss.validate_shares(share),
            "The single share should be valid"
        );
    }

    #[test]
    fn test_invalid_reconstruction_with_fewer_shares() {
        let threshold = 3;
        let total_shares = 5;
        let secret = BigInt::from(1234);
        let mut vss = create_feldman_vss(threshold, total_shares);
        let response = vss.generate_shares(secret.clone()).unwrap();
        // Try to reconstruct the secret with fewer than the required shares
        let reconstructed_secret = vss.reconstruct(&response.shares[0..threshold - 1].to_vec());
        assert!(
            reconstructed_secret.is_err(),
            "Reconstruction should fail with fewer than `threshold` shares"
        );
    }
}
