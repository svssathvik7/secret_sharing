#[cfg(test)]
mod tests {
    use crate::algorithms::{feldman_vss::FeldmanVSS, secret_sharing::SecretSharing};

    use num_bigint::BigInt;

    #[test]
    fn test_invalid_threshold() {
        let threshold = 6; // Threshold larger than total_shares
        let total_shares = 5;
        let _secret = BigInt::from(1234);
        let prime = BigInt::from(2147483647); // Prime number

        let result = FeldmanVSS::new(threshold, total_shares, Some(prime));

        // Expecting an error because threshold is larger than total_shares
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_shares() {
        let threshold = 3;
        let total_shares = 5;
        let secret = BigInt::from(1234);
        let prime = BigInt::from(2147483647); // Prime number

        let mut vss = FeldmanVSS::new(threshold, total_shares, Some(prime)).unwrap();

        // Generate shares and commitments
        let response = vss.generate_shares(secret.clone()).unwrap();

        // Check that the number of shares matches the total shares requested
        assert_eq!(response.shares.len(), total_shares);

        // Check that the number of commitments matches the threshold
        assert_eq!(response.committments.len(), threshold);

        // Ensure the commitments are non-empty
        assert!(!response.committments.is_empty());
    }

    #[test]
    fn test_validate_shares_valid() {
        let threshold = 3;
        let total_shares = 5;
        let secret = BigInt::from(1234);
        let prime = BigInt::from(2147483647); // Prime number

        let mut vss = FeldmanVSS::new(threshold, total_shares, Some(prime)).unwrap();
        let response = vss.generate_shares(secret.clone()).unwrap();
        let share = response.shares[0].clone();

        // Validate the first share
        let is_valid = vss.validate_shares(share);
        assert!(is_valid);
    }

    #[test]
    fn test_validate_shares_invalid() {
        let threshold = 3;
        let total_shares = 5;
        let secret = BigInt::from(1234);
        let prime = BigInt::from(2147483647); // Prime number

        let mut vss = FeldmanVSS::new(threshold, total_shares, Some(prime)).unwrap();
        let response = vss.generate_shares(secret.clone()).unwrap();

        // Create an invalid share by modifying the value
        let mut invalid_share = response.shares[0].clone();
        invalid_share.1 += 1; // Invalid modification to the share value
        println!("{}",invalid_share.1);
        // Validate the invalid share
        let is_valid = vss.validate_shares(invalid_share);
        assert!(!is_valid);
    }

    #[test]
    fn test_reconstruct_secret() {
        let threshold = 3;
        let total_shares = 5;
        let secret = BigInt::from(1234);
        let prime = BigInt::from(2147483647); // Prime number

        let mut vss = FeldmanVSS::new(threshold, total_shares, Some(prime)).unwrap();
        let response = vss.generate_shares(secret.clone()).unwrap();

        // Reconstruct the secret using the first `threshold` number of shares
        let reconstructed_secret = vss.reconstruct(&response.shares).unwrap();

        // Ensure the reconstructed secret matches the original secret
        assert_eq!(reconstructed_secret, secret);
    }
}
