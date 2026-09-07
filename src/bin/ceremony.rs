//! The M-of-K root-ceremony runner (SIGNATIF threshold roots).
//!
//! Real threshold cryptography from `unidpp_signatif::threshold`:
//! Feldman-verifiable Shamir shares and M-of-K Schnorr partials that
//! combine into one standard Ed25519 group signature. The combined
//! signature verifies with any Ed25519 verifier — the group key looks
//! like an ordinary root key; the threshold machinery lives entirely
//! in the ceremony.
//!
//! ```text
//! ceremony init --threshold 2 --members 3 [--seed HEX] --out DIR
//!   DIR/group.json, DIR/member-1.json … (member files are SECRET)
//! ceremony verify-share --group DIR/group.json --share DIR/member-1.json
//! ceremony sign --group DIR/group.json --share DIR/member-1.json \
//!               --share DIR/member-2.json --message statement.bin \
//!               [--out signature.json]
//! ceremony verify --group DIR/group.json --signature signature.json \
//!                 --message statement.bin
//! ```
//!
//! Trust assumptions (see the library docs for the full statement):
//! the dealer who runs `init` sees the whole polynomial for the
//! duration of generation (a lying dealer is caught by every member's
//! `verify-share`); share files travel out of band and stay
//! confidential; the combiner running `sign` learns nothing secret
//! (partials verify against the public commitments); fewer than
//! threshold shares reveal nothing and cannot sign.

use std::process::ExitCode;

use unidpp_signatif::threshold::{
    combine, generate, nonce_point, sign_partial, verify, verify_share, GroupKey, GroupSignature,
    MemberShare,
};

const USAGE: &str = "\
unidpp-signatif ceremony — M-of-K threshold root ceremonies

USAGE:
  ceremony init --threshold <M> --members <K> [--seed <HEX>] --out <DIR>
  ceremony verify-share --group <FILE> --share <FILE>
  ceremony sign --group <FILE> --share <FILE>... --message <FILE> [--out <FILE>]
  ceremony verify --group <FILE> --signature <FILE> --message <FILE>

The group file is public (pin it as the root anchor). Member share
files are SECRET to their member — distribute out of band. A qualifying
set of exactly --threshold shares signs; fewer is refused, a forged
partial aborts with the culprit's index named.

Without --seed, init derives the ceremony from OS entropy (production);
--seed keeps a ceremony reproducible (tests, rehearsals).";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(text) => {
            if !text.is_empty() {
                println!("{text}");
            }
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("ceremony: {message}\n\n{USAGE}");
            ExitCode::FAILURE
        }
    }
}

struct Options {
    threshold: Option<usize>,
    members: Option<usize>,
    seed: Option<String>,
    out: Option<String>,
    group: Option<String>,
    shares: Vec<String>,
    message: Option<String>,
    signature: Option<String>,
}

fn parse(args: &[String]) -> Result<Options, String> {
    let mut options = Options {
        threshold: None,
        members: None,
        seed: None,
        out: None,
        group: None,
        shares: Vec::new(),
        message: None,
        signature: None,
    };
    let mut index = 0;
    while index < args.len() {
        let arg = args[index].as_str();
        let mut value = |flag: &str| -> Result<String, String> {
            index += 1;
            args.get(index)
                .cloned()
                .ok_or_else(|| format!("{flag} needs a value"))
        };
        match arg {
            "--threshold" => {
                let raw = value("--threshold")?;
                options.threshold = Some(
                    raw.parse()
                        .map_err(|_| format!("--threshold `{raw}` is not a number"))?,
                );
            }
            "--members" => {
                let raw = value("--members")?;
                options.members = Some(
                    raw.parse()
                        .map_err(|_| format!("--members `{raw}` is not a number"))?,
                );
            }
            "--seed" => options.seed = Some(value("--seed")?),
            "--out" => options.out = Some(value("--out")?),
            "--group" => options.group = Some(value("--group")?),
            "--share" => options.shares.push(value("--share")?),
            "--message" => options.message = Some(value("--message")?),
            "--signature" => options.signature = Some(value("--signature")?),
            "-h" | "--help" => return Err(String::new()),
            other => return Err(format!("unknown argument `{other}`")),
        }
        index += 1;
    }
    Ok(options)
}

fn run(args: &[String]) -> Result<String, String> {
    let command = args
        .first()
        .ok_or_else(|| "missing command".to_string())?
        .as_str();
    let options = parse(&args[1..]).map_err(|e| if e.is_empty() { String::new() } else { e })?;
    match command {
        "init" => init(&options),
        "verify-share" => verify_share_cmd(&options),
        "sign" => sign(&options),
        "verify" => verify_cmd(&options),
        other => Err(format!("unknown command `{other}`")),
    }
}

fn read(path: &str) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("cannot read {path}: {e}"))
}

fn write(path: &str, text: &str) -> Result<(), String> {
    std::fs::write(path, text).map_err(|e| format!("cannot write {path}: {e}"))
}

fn init(options: &Options) -> Result<String, String> {
    let threshold = options.threshold.ok_or("init needs --threshold")?;
    let members = options.members.ok_or("init needs --members")?;
    let out = options
        .out
        .clone()
        .ok_or("init needs --out (a directory)")?;
    // Without --seed the ceremony derives from OS entropy; with it,
    // reproducibly (the hex may be any length; it is hashed).
    let seed: Vec<u8> = match &options.seed {
        Some(hex) => hex_decode(hex).ok_or_else(|| format!("--seed `{hex}` is not hex"))?,
        None => {
            let mut entropy = [0u8; 32];
            getrandom(&mut entropy).map_err(|e| format!("OS entropy: {e}"))?;
            entropy.to_vec()
        }
    };
    let (group, shares) =
        generate(&seed, threshold, members).map_err(|e| format!("generation: {e}"))?;
    std::fs::create_dir_all(&out).map_err(|e| format!("cannot create {out}: {e}"))?;
    let group_path = format!("{out}/group.json");
    write(
        &group_path,
        &serde_json::to_string_pretty(&group.to_json()).unwrap(),
    )?;
    for share in &shares {
        let path = format!("{out}/member-{}.json", share.index);
        write(
            &path,
            &serde_json::to_string_pretty(&share.to_json()).unwrap(),
        )?;
    }
    Ok(format!(
        "{}-of-{} ceremony generated: {group_path} (public) + {members} member share files (SECRET)\n\
         every member should run: ceremony verify-share --group {group_path} --share <their file>",
        group.threshold, group.members
    ))
}

fn verify_share_cmd(options: &Options) -> Result<String, String> {
    let group_path = options
        .group
        .as_deref()
        .ok_or("verify-share needs --group")?;
    let share_path = options
        .shares
        .first()
        .map(String::as_str)
        .ok_or("verify-share needs --share")?;
    let group =
        GroupKey::from_json(&String::from_utf8(read(group_path)?).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    let share =
        MemberShare::from_json(&String::from_utf8(read(share_path)?).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    if verify_share(&group, &share).map_err(|e| e.to_string())? {
        Ok(format!(
            "member {}: share verifies against the group commitments",
            share.index
        ))
    } else {
        Err(format!(
            "member {}: share does NOT match the group commitments — a lying dealer or a corrupted share",
            share.index
        ))
    }
}

fn sign(options: &Options) -> Result<String, String> {
    let group_path = options.group.as_deref().ok_or("sign needs --group")?;
    let message_path = options.message.as_deref().ok_or("sign needs --message")?;
    if options.shares.is_empty() {
        return Err("sign needs at least one --share".to_string());
    }
    let group =
        GroupKey::from_json(&String::from_utf8(read(group_path)?).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    if options.shares.len() != group.threshold {
        return Err(format!(
            "a qualifying set is exactly {} shares ({} given): fewer cannot sign, more are redundant",
            group.threshold,
            options.shares.len()
        ));
    }
    let message = read(message_path)?;
    let mut shares = Vec::with_capacity(options.shares.len());
    for path in &options.shares {
        shares.push(
            MemberShare::from_json(&String::from_utf8(read(path)?).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?,
        );
    }
    // Round 1: the qualifying set publishes its nonce points; round 2:
    // each member contributes a partial over the group nonce; the
    // combiner verifies every partial against the Feldman commitments
    // and combines into one standard Ed25519 group signature.
    let mut nonces: Vec<(u32, String)> = Vec::with_capacity(shares.len());
    for share in &shares {
        let point = nonce_point(share, &message).map_err(|e| e.to_string())?;
        nonces.push((share.index, point));
    }
    let partials: Vec<_> = shares
        .iter()
        .map(|share| sign_partial(&group, share, &message, &nonces).map_err(|e| e.to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    let signature = combine(&group, &message, &partials).map_err(|e| e.to_string())?;
    let text = serde_json::to_string_pretty(&signature.to_json()).unwrap();
    match &options.out {
        Some(path) => {
            write(path, &text)?;
            Ok(format!("signed by {:?}: {path}", signature.signers))
        }
        None => Ok(text),
    }
}

fn verify_cmd(options: &Options) -> Result<String, String> {
    let group_path = options.group.as_deref().ok_or("verify needs --group")?;
    let signature_path = options
        .signature
        .as_deref()
        .ok_or("verify needs --signature")?;
    let message_path = options.message.as_deref().ok_or("verify needs --message")?;
    let group =
        GroupKey::from_json(&String::from_utf8(read(group_path)?).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    let signature = GroupSignature::from_json(
        &String::from_utf8(read(signature_path)?).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let message = read(message_path)?;
    verify(&group, &message, &signature).map_err(|e| e.to_string())?;
    Ok(format!(
        "group signature verifies: {} signer(s) {:?}, algorithm {}",
        signature.signers.len(),
        signature.signers,
        signature.algorithm
    ))
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok())
        .collect()
}

fn getrandom(bytes: &mut [u8]) -> Result<(), String> {
    use std::io::Read;
    let mut file = std::fs::File::open("/dev/urandom").map_err(|e| e.to_string())?;
    let mut filled = 0;
    while filled < bytes.len() {
        let n = file.read(&mut bytes[filled..]).map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("urandom closed early".to_string());
        }
        filled += n;
    }
    Ok(())
}
