#[cfg(test)]
mod tests{
    use num_bigint::BigInt;

    use crate::algorithms::shamir_secret_sharing::ShamirSecretSharing;    
    #[test]
    fn config_test(){
        let threshold = 2;
        let total_shares = 5;
        let _secret = 1234;
        let shamir = ShamirSecretSharing::new(threshold, total_shares, None).unwrap();

        assert_eq!(shamir.prime,BigInt::from(2147483647));
    }

    #[test]
    fn small_secret_test() {
        let threshold = 2;
        let total_shares = 5;
        let secret = BigInt::from(1234);
        let mut shamir = ShamirSecretSharing::new(threshold, total_shares, None).unwrap();

        let shares = shamir.generate_shares(secret).unwrap();

        // Ensure the correct number of shares are generated
        assert_eq!(shares.len(), total_shares);
    }

    #[test]
    fn large_secret_test() {
        let threshold = 3;
        let total_shares = 5;
        let secret = BigInt::from(9100931);
        let mut shamir = ShamirSecretSharing::new(threshold, total_shares, None).unwrap();

        let shares = shamir.generate_shares(secret).unwrap();

        // Ensure the correct number of shares are generated
        assert_eq!(shares.len(), total_shares);
    }

    #[test]
    fn large_secret_failing_test() {
        let threshold = 3;
        let total_shares = 5;
        // secret larger than the given prime
        let secret = BigInt::from(9100932139u64);
        let mut shamir = ShamirSecretSharing::new(threshold, total_shares, None).unwrap();

        let shares = shamir.generate_shares(secret);

        // Ensure the correct number of shares are generated
        assert!(shares.is_err());
        
    }

    #[test]
    fn small_threshold_test() {
        let threshold = 2;
        let total_shares = 5;
        let secret = BigInt::from(1234);
        let mut shamir = ShamirSecretSharing::new(threshold, total_shares, None).unwrap();

        let shares = shamir.generate_shares(secret).unwrap();

        // Ensure the correct number of shares are generated
        assert_eq!(shares.len(), total_shares);

        // Check that the threshold is correct
        assert_eq!(shamir.threshold, threshold);
    }

    #[test]
    fn large_threshold_test() {
        let threshold = 10;
        let total_shares = 15;
        let secret = BigInt::from(1234);
        let mut shamir = ShamirSecretSharing::new(threshold, total_shares, None).unwrap();

        let shares = shamir.generate_shares(secret).unwrap();

        // Ensure the correct number of shares are generated
        assert_eq!(shares.len(), total_shares);

        // Check that the threshold is correct
        assert_eq!(shamir.threshold, threshold);
    }
}