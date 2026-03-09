//! Poseidon2 hash CLI for SignedByMe
//!
//! Usage:
//!   poseidon_hash leaf_commit <leaf_secret_hex>
//!   poseidon_hash pair <left_hex> <right_hex>
//!   poseidon_hash zero
//!   poseidon_hash zeros <depth>
//!
//! Output: hex-encoded 32-byte hash

use std::env;
use std::process::exit;

// Import from parent crate
use groth16_verifier::poseidon::{compute_leaf_commitment, merkle_hash_pair, zero_hash, compute_zero_hashes};

fn print_usage() {
    eprintln!("Usage:");
    eprintln!("  poseidon_hash leaf_commit <leaf_secret_hex>  - Compute leaf commitment");
    eprintln!("  poseidon_hash pair <left_hex> <right_hex>    - Compute Merkle node hash");
    eprintln!("  poseidon_hash zero                           - Output zero hash");
    eprintln!("  poseidon_hash zeros <depth>                  - Output zero hashes for tree");
    eprintln!();
    eprintln!("All hex values should be 64 characters (32 bytes), with or without 0x prefix.");
}

fn parse_hex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).map_err(|e| format!("Invalid hex: {}", e))
}

fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        print_usage();
        exit(1);
    }
    
    let command = &args[1];
    
    match command.as_str() {
        "leaf_commit" => {
            if args.len() != 3 {
                eprintln!("Error: leaf_commit requires exactly one argument");
                print_usage();
                exit(1);
            }
            
            let secret = match parse_hex(&args[2]) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    exit(1);
                }
            };
            
            if secret.len() != 32 {
                eprintln!("Error: leaf_secret must be 32 bytes (64 hex chars), got {} bytes", secret.len());
                exit(1);
            }
            
            match compute_leaf_commitment(&secret) {
                Ok(hash) => println!("{}", hex::encode(hash)),
                Err(e) => {
                    eprintln!("Error: {}", e);
                    exit(1);
                }
            }
        }
        
        "pair" => {
            if args.len() != 4 {
                eprintln!("Error: pair requires exactly two arguments");
                print_usage();
                exit(1);
            }
            
            let left = match parse_hex(&args[2]) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Error parsing left: {}", e);
                    exit(1);
                }
            };
            
            let right = match parse_hex(&args[3]) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Error parsing right: {}", e);
                    exit(1);
                }
            };
            
            if left.len() != 32 {
                eprintln!("Error: left must be 32 bytes, got {} bytes", left.len());
                exit(1);
            }
            
            if right.len() != 32 {
                eprintln!("Error: right must be 32 bytes, got {} bytes", right.len());
                exit(1);
            }
            
            match merkle_hash_pair(&left, &right) {
                Ok(hash) => println!("{}", hex::encode(hash)),
                Err(e) => {
                    eprintln!("Error: {}", e);
                    exit(1);
                }
            }
        }
        
        "zero" => {
            match zero_hash() {
                Ok(hash) => println!("{}", hex::encode(hash)),
                Err(e) => {
                    eprintln!("Error: {}", e);
                    exit(1);
                }
            }
        }
        
        "zeros" => {
            if args.len() != 3 {
                eprintln!("Error: zeros requires depth argument");
                print_usage();
                exit(1);
            }
            
            let depth: usize = match args[2].parse() {
                Ok(d) => d,
                Err(_) => {
                    eprintln!("Error: depth must be a positive integer");
                    exit(1);
                }
            };
            
            if depth == 0 || depth > 32 {
                eprintln!("Error: depth must be between 1 and 32");
                exit(1);
            }
            
            match compute_zero_hashes(depth) {
                Ok(zeros) => {
                    for (i, z) in zeros.iter().enumerate() {
                        println!("{}:{}", i, hex::encode(z));
                    }
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    exit(1);
                }
            }
        }
        
        _ => {
            eprintln!("Error: Unknown command '{}'", command);
            print_usage();
            exit(1);
        }
    }
}
