use algorithms::{feldman_vss::FeldmanVSS, secret_sharing::SecretSharing, shamir_secret_sharing::ShamirSecretSharing};
use num_bigint::BigInt;
pub mod tests;
pub mod algorithms;
fn main(){
    let threshold = 2;
    let secret = BigInt::from(786);
    let total_shares = 5;
    let mut shamir = ShamirSecretSharing::new(threshold, total_shares, None).unwrap();
    let shares = shamir.generate_shares(secret.clone()).unwrap();
    println!("----------------Shamir Secret Sharing----------------");
    println!("Secret : {}",secret);
    println!("Generated shares for {} with n={} t={}\n{:?}",secret,total_shares,threshold,shares);

    let recovered_secret = shamir.reconstruct(&shares).unwrap();

    println!("Recovered secret {}\n",recovered_secret);
    println!("------------------------------------------------------");


    let mut feldman = FeldmanVSS::new(threshold, total_shares, None).unwrap();

    let response = feldman.generate_shares(secret.clone()).unwrap();
    let shares = response.shares;
    println!("----------------------Feldman VSS----------------------");
    println!("Secret : {}",secret);
    println!("Generated shares for {} with n={} t={}\n{:?}",secret,total_shares,threshold,shares);
    println!("Validating all shares : ");
    for share in shares.clone(){
        println!("{:?} validity is {}",share,feldman.validate_shares(share.clone()));
    }
    let recovered_secret = feldman.reconstruct(&shares).unwrap();
    println!("Recovered secret is {}",recovered_secret);
    println!("--------------------------------------------------------");
}