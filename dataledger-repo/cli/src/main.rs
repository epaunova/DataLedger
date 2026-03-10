use std::fs;
use std::path::PathBuf;
use dataledger_core::{Manifest, Attestation};

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        print_usage();
        std::process::exit(1);
    }

    let result = match (args[1].as_str(), args.get(2).map(String::as_str)) {
        ("manifest", Some("verify")) => cmd_manifest_verify(&args[3..]),
        ("manifest", Some("inspect")) => cmd_manifest_inspect(&args[3..]),
        ("attest",   Some("verify"))  => cmd_attest_verify(&args[3..]),
        _ => { print_usage(); std::process::exit(1); }
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn cmd_manifest_verify(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let path = args.first().ok_or("usage: dataledger manifest verify <manifest.json>")?;
    let json = fs::read_to_string(PathBuf::from(path))?;
    let manifest = Manifest::from_json(&json)?;
    manifest.verify()?;
    println!("OK  manifest verified successfully");
    println!("    id:      {}", manifest.id);
    println!("    name:    {}", manifest.name);
    println!("    version: {}", manifest.version);
    Ok(())
}

fn cmd_manifest_inspect(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let path = args.first().ok_or("usage: dataledger manifest inspect <manifest.json>")?;
    let json = fs::read_to_string(PathBuf::from(path))?;
    let manifest = Manifest::from_json(&json)?;
    let status = if manifest.verify().is_ok() { "VALID" } else { "INVALID" };
    println!("Manifest");
    println!("  Signature status : {status}");
    println!("  id               : {}", manifest.id);
    println!("  name             : {}", manifest.name);
    println!("  version          : {}", manifest.version);
    println!("  source_uri       : {}", manifest.source_uri);
    println!("  licence          : {}", manifest.licence);
    println!("  content_hash     : {}", manifest.content_hash);
    println!("  created_at       : {}", manifest.created_at);
    println!("  publisher_key    : {}...", &manifest.publisher_key[..16]);
    if let Some(splits) = &manifest.splits {
        println!("  splits ({}):", splits.len());
        for s in splits {
            println!("    {} : {} files, {} rows", s.name, s.file_count, s.row_count);
        }
    }
    Ok(())
}

fn cmd_attest_verify(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let path = args.first().ok_or("usage: dataledger attest verify <attestation.json>")?;
    let json = fs::read_to_string(PathBuf::from(path))?;
    let attestation = Attestation::from_json(&json)?;
    attestation.verify_hash()?;
    println!("OK  attestation hash verified");
    println!("    run_id   : {}", attestation.run_id);
    println!("    model_id : {}", attestation.model_id);
    println!("    datasets : {}", attestation.manifests_consumed.len());
    Ok(())
}

fn print_usage() {
    println!("dataledger -- DataLedger CLI");
    println!();
    println!("USAGE:");
    println!("  dataledger manifest verify  <manifest.json>");
    println!("  dataledger manifest inspect <manifest.json>");
    println!("  dataledger attest   verify  <attestation.json>");
}
