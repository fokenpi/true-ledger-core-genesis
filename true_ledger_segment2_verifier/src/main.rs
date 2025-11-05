/*
 * TRUE LEDGER CORE - SEGMENT 2: TRANSACTION VERIFICATION
 * This program loads the signed transaction, verifies its cryptographic
 * signature, and checks for financial balance.
 */
use ed25519_dalek::{Verifier, PublicKey, Signature};
use sha2::{Sha256, Digest};
use serde::{Deserialize, Serialize};
use std::fs;
use hex;

// --- 1. Data Models (Must match Segment 1) ---
#[derive(Serialize, Deserialize, Debug, Clone)]
struct JournalEntry {
    account_id: String,
    debit: String,
    credit: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct Transaction {
    timestamp: u64,           
    author_did: String,       
    entries: Vec<JournalEntry>, 
    memo: String,             
}

#[derive(Serialize, Deserialize, Debug)]
struct SignedTransaction {
    payload: Transaction,
    signature: String,       
}

impl Transaction {
    /// Generates the hash of the payload for verification
    fn get_hash(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        let data = serde_json::to_string(&self)
            .expect("Failed to serialize transaction for hashing");
        hasher.update(data.as_bytes());
        hasher.finalize().to_vec()
    }
}

// --- 2. Core Verification Functions ---

/// Helper to parse a did:key and extract the Ed25519 public key
fn did_to_public_key(did: &str) -> Result<PublicKey, String> {
    if !did.starts_with("did:key:z6Mk") {
        return Err("Not an Ed25519 did:key".to_string());
    }
    
    // Extract the base58 part of the DID
    let key_str = &did[8..]; 
    
    // Decode from Base58btc
    let decoded = multibase::decode(multibase::Base::Base58Btc, key_str)
        .map_err(|e| format!("Multibase decode error: {:?}", e))?;

    // Check for 0xed01 multicodec prefix (Ed25519)
    if decoded.len() > 2 && decoded[0] == 0xed && decoded[1] == 0x01 {
        // The public key starts after the 2-byte prefix
        PublicKey::from_bytes(&decoded[2..])
            .map_err(|e| format!("Invalid public key bytes: {:?}", e))
    } else {
        Err("Invalid multicodec prefix for Ed25519".to_string())
    }
}

/// Verifies the cryptographic signature against the transaction hash
fn verify_signature(signed_tx: &SignedTransaction) -> Result<bool, String> {
    // 1. Get the Public Key from the DID (Authentication)
    let public_key = did_to_public_key(&signed_tx.payload.author_did)?;

    // 2. Get the Signature
    let signature_bytes = hex::decode(&signed_tx.signature)
        .map_err(|e| format!("Invalid hex signature: {:?}", e))?;
    let signature = Signature::from_bytes(&signature_bytes)
        .map_err(|e| format!("Invalid signature format: {:?}", e))?;

    // 3. Get the Hash of the payload (Integrity)
    let tx_hash = signed_tx.payload.get_hash();

    // 4. Verify the signature against the hash
    if public_key.verify(&tx_hash, &signature).is_ok() {
        Ok(true)
    } else {
        Err("Signature verification failed: Tampering detected or wrong key.".to_string())
    }
}

/// IFRS/Accounting Check: Ensures total debits equal total credits
fn verify_balance(tx: &Transaction) -> Result<(), String> {
    let mut total_debits: f64 = 0.0;
    let mut total_credits: f64 = 0.0;

    for entry in &tx.entries {
        // Use parse() on String amounts. We must handle potential parsing errors!
        total_debits += entry.debit.parse::<f64>()
            .map_err(|_| "Invalid debit amount format (Not a number).".to_string())?;
        total_credits += entry.credit.parse::<f64>()
            .map_err(|_| "Invalid credit amount format (Not a number).".to_string())?;
    }

    // Check for equality (use small tolerance for float comparison, though strings are safer)
    if (total_debits - total_credits).abs() < 0.0001 {
        Ok(())
    } else {
        Err(format!("Financial imbalance detected: Debits ({}) != Credits ({})", total_debits, total_credits))
    }
}


// --- 3. Main Logic ---
fn main() {
    println!("--- True Ledger Core: Segment 2 (Verification) ---");
    let file_path = "../true_ledger_segment1/genesis_transaction.json";

    // 1. Load the file from Segment 1
    let json_data = match fs::read_to_string(file_path) {
        Ok(data) => {
            println!("💾 Loaded file: {}", file_path);
            data
        },
        Err(_) => {
            eprintln!("❌ Error: Could not find or read the genesis_transaction.json file.");
            eprintln!("   Please ensure you ran Segment 1 successfully.");
            return;
        }
    };

    // 2. Deserialize the data
    let signed_tx: SignedTransaction = match serde_json::from_str(&json_data) {
        Ok(tx) => tx,
        Err(e) => {
            eprintln!("❌ Error: Failed to parse transaction data: {}", e);
            return;
        }
    };
    
    println!("\n🔍 Attempting full verification...");

    // 3. Cryptographic Verification (Security/Immutability)
    match verify_signature(&signed_tx) {
        Ok(true) => {
            println!("✅ Cryptographic Signature: VALID");
            println!("   > Data integrity confirmed. Author authenticated.");
        },
        Err(e) => {
            println!("❌ Cryptographic Signature: FAILED");
            println!("   > Reason: {}", e);
            return;
        }
    }

    // 4. Financial Verification (IFRS Compliance)
    match verify_balance(&signed_tx.payload) {
        Ok(_) => {
            println!("✅ Financial Balance: VALID");
            println!("   > Debits equal Credits. IFRS principle upheld.");
        },
        Err(e) => {
            println!("❌ Financial Balance: FAILED");
            println!("   > Reason: {}", e);
            return;
        }
    }

    println!("\n🎉 **TRANSACTION IS VERIFIED AND VALID**");
    println!("--- Segment 2 Complete ---");
}