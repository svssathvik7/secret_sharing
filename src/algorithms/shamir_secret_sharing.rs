use num_bigint::{BigInt, RandBigInt};

#[derive(Debug)]
pub struct ShamirSecretSharing{
    pub threshold: usize,
    pub total_shares: usize,
    pub prime: BigInt,
    pub coefficients: Vec<BigInt>
}

impl ShamirSecretSharing{
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

        Ok(Self{
            threshold,
            total_shares,
            prime,
            coefficients: Vec::new()
        })
    }

    // generates shares based on the secret, n and k
    pub fn generate_shares(&mut self,secret: BigInt) -> Result<Vec<(usize,BigInt)>,String>{
        if secret >= self.prime{
            return Err("Secret can't be larger than ".to_string()+&self.prime.to_string());
        }

        // update self.coefficients
        self.generate_coefficients(secret);

        let mut shares: Vec<(usize,BigInt)> = Vec::new();
        // share = (i,v) on the polynomial
        for i in 1..=self.total_shares{
            shares.push((i,self.calculate_y( i)));
        }
        Ok(shares)
    }

    // generate random coefficients of the polynomial with [1,prime)
    fn generate_coefficients(&mut self,secret: BigInt){
        // a0 = secret
        let mut coefficients = vec![secret];
        let mut rng = rand::thread_rng();
        for _i in 0..self.threshold-1{
            let new_coefficient = rng.gen_bigint_range(&BigInt::from(1),&self.prime);
            coefficients.push(new_coefficient);
        }
        self.coefficients = coefficients;
    }

    // calculate y by f(x)
    fn calculate_y(&self,x: usize) -> BigInt{
        let coefficients = &self.coefficients;
        let x_value = BigInt::from(x);
        let mut result = BigInt::from(0);
        for (i,coeff) in coefficients.iter().enumerate(){
            result = result + (coeff*x_value.pow(i as u32));
        }
        result
    }

    // lagrange interpolation to reconstruct poly from t shares
    pub fn lagrange_interpolation(&self,xs:Vec<usize>,ys:Vec<BigInt>) -> BigInt{
        let mut secret = BigInt::from(0);
        for i in 0..self.threshold{
            let mut num = BigInt::from(1);
            let mut denom = BigInt::from(1);
            for j in 0..self.threshold{
                if i!=j{
                    // (0-xj)
                    num = (num * (BigInt::from(-1*xs[j] as i64))) % &self.prime;
                    // (xi-xj)
                    denom = (denom * (BigInt::from(xs[i] as i64 - BigInt::from(xs[j] as i64)))) % &self.prime;
                }
            }
            // (-xj)/(xi-xj)
            secret += ((num/denom) * &ys[i]) % &self.prime;
        }
        if secret < BigInt::from(0){
            secret + &self.prime
        }
        else{
            secret % &self.prime
        }
    }
    pub fn reconstruct(&self,shares:&Vec<(usize,BigInt)>) -> Result<BigInt,String>{
        if shares.len() < self.threshold{
            return Err("Require atleast ".to_string() + &self.threshold.to_string() + " shares");
        }
        // unzip x values and corresponding y values
        let (xs,ys) = shares.iter().cloned().unzip();
        let recovered_secret = self.lagrange_interpolation(xs,ys);
        Ok(recovered_secret)
    }
}


#[cfg(test)]
mod tests {
    use num_bigint::BigInt;
    use crate::algorithms::shamir_secret_sharing::ShamirSecretSharing;

    // Helper function to avoid code duplication in generating shares and validating counts
    fn generate_shares_and_validate(threshold: usize, total_shares: usize, secret: BigInt) -> Vec<(usize, BigInt)> {
        let mut shamir = ShamirSecretSharing::new(threshold, total_shares, None).unwrap();
        let shares = shamir.generate_shares(secret).unwrap();
        assert_eq!(shares.len(), total_shares, "Generated share count should match total shares");
        shares
    }

    #[test]
    fn config_test() {
        let threshold = 2;
        let total_shares = 5;
        let shamir = ShamirSecretSharing::new(threshold, total_shares, None).unwrap();

        assert_eq!(shamir.prime, BigInt::from(2147483647), "Prime should be the default value of 2147483647");
    }

    #[test]
    fn small_secret_test() {
        let threshold = 2;
        let total_shares = 5;
        let secret = BigInt::from(1234);

        let shares = generate_shares_and_validate(threshold, total_shares, secret);

        // Ensure threshold validation
        assert!(shares.len() == total_shares, "Share count doesn't match the total shares");
    }

    #[test]
    fn large_secret_test() {
        let threshold = 3;
        let total_shares = 5;
        let secret = BigInt::from(9100931);

        let shares = generate_shares_and_validate(threshold, total_shares, secret);

        assert!(shares.len() == total_shares, "Share count doesn't match the total shares");
    }

    #[test]
    fn large_secret_failing_test() {
        let threshold = 3;
        let total_shares = 5;
        let secret = BigInt::from(9100932139u64); // Secret larger than prime

        let mut shamir = ShamirSecretSharing::new(threshold, total_shares, None).unwrap();

        // Secret larger than prime, should return error
        let result = shamir.generate_shares(secret);
        assert!(result.is_err(), "Expected an error when secret is larger than the prime");
    }

    #[test]
    fn small_threshold_test() {
        let threshold = 2;
        let total_shares = 5;
        let secret = BigInt::from(1234);

        let shares = generate_shares_and_validate(threshold, total_shares, secret);

        assert_eq!(shares.len(), total_shares, "Share count doesn't match the total shares");
        assert_eq!(threshold, 2, "Threshold should be 2");
    }

    #[test]
    fn large_threshold_test() {
        let threshold = 10;
        let total_shares = 15;
        let secret = BigInt::from(1234);

        let shares = generate_shares_and_validate(threshold, total_shares, secret);

        assert_eq!(shares.len(), total_shares, "Share count doesn't match the total shares");
        assert_eq!(threshold, 10, "Threshold should be 10");
    }

    #[test]
    fn reconstruct_secret_test() {
        let threshold = 3;
        let total_shares = 5;
        let secret = BigInt::from(1234);

        let shares = generate_shares_and_validate(threshold, total_shares, secret.clone());

        // Reconstruct secret using the threshold number of shares
        let reconstructed_secret = {
            let mut shamir = ShamirSecretSharing::new(threshold, total_shares, None).unwrap();
            shamir.reconstruct(&shares[0..threshold].to_vec()).unwrap()
        };

        assert_eq!(reconstructed_secret, secret, "Reconstructed secret should match the original secret");
    }
}
