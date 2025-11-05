/*
 * TRUE LEDGER CORE - SEGMENT 1: THE GENESIS TRANSACTION
 * This program creates an identity, defines a sample double-entry
 * transaction, signs it, and saves it to a file.
 * NOTE: Uses ed25519-dalek 1.0.1 for stable import paths.
 */

// --- Import necessary tools ---
// The original error was resolved by importing PublicKey and Keypair from the root.
// Version 1.0.1 correctly exposes these in the root.
use ed25519_dalek::{Keypair, Signer, Verifier, PublicKey}; 
use rand::rngs::OsRng;
use sha2::{Sha256, Digest};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Write;
use hex; // Already added to Cargo.toml

// --- 1. Identity Model (The Account) ---
// This holds our keys and the public DID.
struct Account {
    keypair: Keypair,
    did: String,
}

impl Account {
    /// Generates a new user account and their 'did:key'
    fn new() -> Self {
        let mut csprng = OsRng{};
        let keypair: Keypair = Keypair::generate(&mut csprng);
        
        // Convert public key to 'did:key:z6Mk...' format (The DID)
        let pub_key_bytes = keypair.public.to_bytes();
        let mut did_key_bytes = vec![0xed, 0x01]; // Ed25519 multicodec prefix
        did_key_bytes.extend_from_slice(&pub_key_bytes);
        let did = format!("did:key:{}", multibase::encode(multibase::Base::Base58Btc, did_key_bytes));

        println!("✅ New Account Created!");
        println!("   DID: {}", did);

        Account { keypair, did }
    }
}

// --- 2. Data Models (The Ledger Objects) ---
// These are the "structs" that define our accounting data.

#[derive(Serialize, Deserialize, Debug, Clone)]
struct JournalEntry {
    account_id: String, // e.g., "10100" (Assets:Cash)
    debit: String,      // Amount as string for precision
    credit: String,     // Amount as string
}

#[derive(Serialize, Deserialize, Debug)]
struct Transaction {
    timestamp: u64,           
    author_did: String,       // The 'did:key' of the creator
    entries: Vec<JournalEntry>, // The list of balanced entries
    memo: String,             // Justification
}

#[derive(Serialize, Deserialize, Debug)]
struct SignedTransaction {
    payload: Transaction,    // The raw transaction data
    signature: String,       // Hex-encoded signature
}

impl Transaction {
    /// Creates a secure hash of the transaction data
    /// This hash is what gets signed.
    fn get_hash(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        let data = serde_json::to_string(&self)
            .expect("Failed to serialize transaction for hashing");
        hasher.update(data.as_bytes());
        hasher.finalize().to_vec()
    }
}

// --- 3. The Main Program Logic ---
fn main() {
    println!("--- True Ledger Core: Segment 1 (IFRS Genesis Block) ---");

    // --- Step A: Generate Identity ---
    let account = Account::new();

    // --- Step B: Create a Transaction (Financial Logic) ---
    // Owner's initial capital contribution.
    let genesis_tx = Transaction {
        timestamp: 1730814442, // Example timestamp
        author_did: account.did.clone(),
        memo: "Initial capital contribution by owner.".to_string(),
        entries: vec![
            JournalEntry {
                account_id: "10100".to_string(), // Assets:Cash (Debit)
                debit: "10000.00".to_string(),
                credit: "0.00".to_string(),
            },
            JournalEntry {
                account_id: "30100".to_string(), // Equity:Owner's Capital (Credit)
                debit: "0.00".to_string(),
                credit: "10000.00".to_string(),
            },
        ],
    };

    println!("\n📝 Creating Genesis Transaction...");

    // --- Step C: Sign the Transaction (Security Model Immutability) ---
    // We sign the *hash* of the transaction data.
    let tx_hash = genesis_tx.get_hash();
    let signature = account.keypair.sign(&tx_hash);
    
    let signed_genesis_tx = SignedTransaction {
        payload: genesis_tx,
        signature: hex::encode(signature.to_bytes()), // Store sig as hex
    };

    println!("\n🔐 Transaction Signed! (CID = hash of content)");

    // --- Step D: Save to File (Local Persistence) ---
    let file_path = "genesis_transaction.json";
    let data_to_save = serde_json::to_string_pretty(&signed_genesis_tx)
        .expect("Failed to serialize to JSON");

    let mut file = File::create(file_path)
        .expect("Failed to create file");
    file.write_all(data_to_save.as_bytes())
        .expect("Failed to write to file");

    println!("\n💾 Success! Verifiable transaction saved to:");
    println!("   {}", file_path);
    println!("\n--- Segment 1 Complete ---");
}