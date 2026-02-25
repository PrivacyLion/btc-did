//! SignedByMe Groth16 Verifier
//! 
//! Verifies membership proofs and extracts the NOSTR npub.

use std::fs;
use std::path::PathBuf;
use std::time::Instant;

mod verifier;
mod types;

use verifier::Verifier;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    
    if args.len() < 4 {
        eprintln!("Usage: {} <verification_key.json> <proof.json> <public.json>", args[0]);
        std::process::exit(1);
    }
    
    let vk_path = PathBuf::from(&args[1]);
    let proof_path = PathBuf::from(&args[2]);
    let public_path = PathBuf::from(&args[3]);
    
    // Load files
    let vk_json = fs::read_to_string(&vk_path)?;
    let proof_json = fs::read_to_string(&proof_path)?;
    let public_json = fs::read_to_string(&public_path)?;
    
    // Initialize verifier
    let start = Instant::now();
    let verifier = Verifier::from_json(&vk_json)?;
    let vk_load_time = start.elapsed();
    
    // Parse proof and public inputs
    let start = Instant::now();
    let proof = verifier.parse_proof(&proof_json)?;
    let public_inputs = verifier.parse_public_inputs(&public_json)?;
    let parse_time = start.elapsed();
    
    // Verify
    let start = Instant::now();
    let valid = verifier.verify(&proof, &public_inputs)?;
    let verify_time = start.elapsed();
    
    if valid {
        println!("✓ Proof verified successfully!");
        println!();
        
        // Extract npub from public inputs
        let npub_result = verifier.extract_npub(&public_inputs)?;
        
        println!("Public Outputs:");
        println!("  merkle_root: {}", npub_result.merkle_root);
        println!("  npub_x:      {}", npub_result.npub_x_hex);
        println!("  npub_y:      {}", npub_result.npub_y_hex);
        println!("  npub (compressed): {}", npub_result.npub_compressed);
        println!();
        println!("Timing:");
        println!("  VK load:    {:?}", vk_load_time);
        println!("  Parse:      {:?}", parse_time);
        println!("  Verify:     {:?}", verify_time);
        println!("  Total:      {:?}", vk_load_time + parse_time + verify_time);
    } else {
        eprintln!("✗ Proof verification FAILED!");
        std::process::exit(1);
    }
    
    Ok(())
}
