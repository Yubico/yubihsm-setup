/*
 * Copyright 2015-2018 Yubico AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

extern crate rusty_secrets;
extern crate yubihsmrs;

#[macro_use]
extern crate clap;

#[macro_use]
extern crate lazy_static;

extern crate regex;

extern crate base64;

extern crate scan_dir;

use regex::Regex;

use std::io;
use std::io::Write;

use std::error::Error;

use std::fs::File;
use std::io::prelude::*;

use yubihsmrs::object::{
    AsymmetricKey, ObjectAlgorithm, ObjectCapability, ObjectDomain, ObjectType,
};
use yubihsmrs::YubiHsm;

use clap::{App, AppSettings, Arg, SubCommand};

use scan_dir::ScanDir;

const WRAPKEY_LEN: usize = 32;

const EJBCA_ATTESTATION_TEMPLATE: &str =
    "MIIC+jCCAeKgAwIBAgIGAWbt9mc3MA0GCSqGSIb3DQEBBQUAMD4xPDA6BgNVBAMM\
     M0R1bW15IGNlcnRpZmljYXRlIGNyZWF0ZWQgYnkgYSBDRVNlQ29yZSBhcHBsaWNh\
     dGlvbjAeFw0xODExMDcxMTM3MjBaFw00ODEwMzExMTM3MjBaMD4xPDA6BgNVBAMM\
     M0R1bW15IGNlcnRpZmljYXRlIGNyZWF0ZWQgYnkgYSBDRVNlQ29yZSBhcHBsaWNh\
     dGlvbjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMTxMBMtwHJCzNHi\
     d0GszdXM49jQdEZOuaLK1hyIjpuhRImJYbdvmF5cYa2suR2yw6DygWGFLafqVEuL\
     dXvnib3r0jBX2w7ZSrPWuJ592QUgNllHCvNG/dNgwLfCVOr9fs1ifJaa09gtQ2EG\
     3iV7j3AMxb7rc8x4d3nsJad+UPCyqB3HXGDRLbOT38zI72zhXm4BqiCMt6+2rcPE\
     +nneNiTMVjrGwzbZkCak6xnwq8/tLTtvD0+yPLQdKb4NaQfXPmYNTrzTmvYmVD8P\
     0bIUo/CoXIh0BkJXwHzX7J9nDW9Qd7BR2Q2vbUaou/STlWQooqoTnVnEK8zvAXkl\
     ubqSUPMCAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAGXwmRWewOcbPV/Jx6wkNDOvE\
     oo4bieBqeRyU/XfDYbuevfNSBnbQktThl1pR21hrJ2l9qV3D1AJDKck/x74hyjl9\
     mh37eqbPAdfx3yY7vN03RYWr12fW0kLJA9bsm0jYdJN4BHV/zCXlSqPS0The+Zfg\
     eVCiQCnEZx/z1jfxwIIg6N8Y7luPWIi36XsGqI75IhkJFw8Jup5HIB4p4P0txinm\
     hxzAwAjKm7yCiBA5oxX1fvSPdlwMb9mcO7qC5wKrsMyuzIpllBbGaCRFCcAtu9Zu\
     MvBJNrMLPK3bz4QvT5dYW/cXcjJbnIDqQKqSVV6feYk3iyS07HkaPGP3rxGpdQ==";

lazy_static! {
    static ref SHARE_RE: Regex = Regex::new(r"^\d-\d-[a-zA-Z0-9+/]{70}$").unwrap();
}

#[derive(Debug)]
enum BooleanAnswer {
    Yes,
    No,
}

impl BooleanAnswer {
    fn from_str(value: &str) -> Result<BooleanAnswer, String> {
        let lowercase = value.to_lowercase();
        match lowercase.as_ref() {
            "y" | "yes" => Ok(BooleanAnswer::Yes),
            "n" | "no" => Ok(BooleanAnswer::No),
            _ => Err(format!("Unable to parse {}", value)),
        }
    }
}

impl Into<bool> for BooleanAnswer {
    fn into(self) -> bool {
        match self {
            BooleanAnswer::Yes => true,
            BooleanAnswer::No => false,
        }
    }
}

fn read_line_or_die() -> String {
    let mut line = String::new();
    match io::stdin().read_line(&mut line) {
        Ok(_) => line.trim().to_owned(),
        Err(err) => {
            println!("Unable to read from stdin: {}", err);
            std::process::exit(1)
        }
    }
}

#[cfg(target_os = "windows")]
fn clear_screen() {
    std::process::Command::new("cmd")
        .args(&["/C", "cls"])
        .status()
        .unwrap_or_else(|err| {
            println!("Unable to clear terminal screen: {}", err);
            std::process::exit(1);
        });
}

#[cfg(not(target_os = "windows"))]
fn clear_screen() {
    std::process::Command::new("clear")
        .status()
        .unwrap_or_else(|err| {
            println!("Unable to clear terminal screen: {}", err);
            std::process::exit(1);
        });
}

fn get_boolean_answer(prompt: &str) -> BooleanAnswer {
    loop {
        print!("{} (y/n) ", prompt);
        std::io::stdout().flush().expect("Unable to flush stdout");
        match BooleanAnswer::from_str(&read_line_or_die()) {
            Ok(a) => {
                break a;
            }
            _ => {
                continue;
            }
        }
    }
}

fn get_integer<T>(prompt: &str, accept_zero: bool) -> T
where
    T: std::str::FromStr,
    T: std::convert::From<u16>, // NOTE(adma): a FromStrRadix trait would be better
{
    loop {
        print!("{} ", prompt);
        std::io::stdout().flush().expect("Unable to flush stdout");
        let line = read_line_or_die();

        let parsed = if line.starts_with("0x") {
            u16::from_str_radix(&line[2..], 16)
        } else {
            line.parse()
        };

        match parsed {
            Ok(a) => {
                if a == 0 && !accept_zero {
                    continue;
                }

                break a.into();
            }
            _ => {
                continue;
            }
        }
    }
}

fn get_domains(prompt: &str) -> Vec<yubihsmrs::object::ObjectDomain> {
    loop {
        print!("{} ", prompt);
        std::io::stdout().flush().expect("Unable to flush stdout");
        match yubihsmrs::object::ObjectDomain::vec_from_str(&read_line_or_die()) {
            Ok(a) => {
                if a.is_empty() {
                    println!("You must select at least one domain");
                    continue;
                }

                if a.len() != 1 {
                    if get_boolean_answer("You have selected more than one domain, are you sure?")
                        .into()
                    {
                        break a;
                    } else {
                        continue;
                    }
                }
                println!("Using domains: {:#?}", a);
                break a;
            }
            _ => {
                println!("Domains format is \"all\" or 1:2:3:...");
                continue;
            }
        }
    }
}

fn get_string(prompt: &str) -> String {
    print!("{} ", prompt);
    std::io::stdout().flush().expect("Unable to flush stdout");
    read_line_or_die()
}

fn get_threshold_and_shares() -> (u32, u32) {
    let mut shares;
    let mut threshold;

    loop {
        shares = get_integer("Enter the number of shares:", false);
        threshold = get_integer("Enter the privacy threshold:", false);

        if shares == 0 || threshold == 0 {
            println!("The number of shares and the privacy threshold must be greater than zero");
            continue;
        }

        if threshold == 1
            && !Into::<bool>::into(get_boolean_answer(
                "You have chosen a privacy threshold of one.\n\
                 The resulting share(s) will contain the unmodified raw wrap key in plain text.\n\
                 Make sure you understand the implications.\nContinue anyway?",
            ))
        {
            continue;
        }

        if threshold > shares {
            println!("The number of shares must be greater than or equal to the privacy threshold");
            continue;
        }

        break (threshold, shares);
    }
}

fn object_to_file(id: u16, object_type: ObjectType, data: &[u8]) -> Result<String, String> {
    let path_string = format!("./0x{:04x}-{}.yhw", id, object_type);
    let path = std::path::Path::new(&path_string);

    let mut file = match std::fs::File::create(&path) {
        Err(why) => panic!("couldn't create {}: {}", path.display(), why.description()),
        Ok(file) => file,
    };

    match file.write_all(base64::encode(data).as_bytes()) {
        Err(why) => Err(why.description().to_string()),
        Ok(_) => Ok(path_string.to_owned()),
    }
}

fn delete_object(session: &yubihsmrs::Session, object_id: u16, object_type: ObjectType) {
    session
        .delete_object(object_id, object_type)
        .unwrap_or_else(|err| {
            println!("Unable to delete object 0x{:04x}: {}", object_id, err);
            std::process::exit(1);
        });
}

fn split_wrapkey(
    wrap_id: u16,
    domains: &[ObjectDomain],
    capabilities: &[ObjectCapability],
    delegated: &[ObjectCapability],
    key_data: &[u8],
    threshold: u32,
    shares: u32,
) {
    let mut data = Vec::<u8>::new();

    data.push(((wrap_id >> 8) & 0xff) as u8);
    data.push((wrap_id & 0xff) as u8);

    data.append(&mut yubihsmrs::object::ObjectDomain::bytes_from_slice(
        domains,
    ));

    data.append(&mut yubihsmrs::object::ObjectCapability::bytes_from_slice(
        capabilities,
    ));

    data.append(&mut yubihsmrs::object::ObjectCapability::bytes_from_slice(
        delegated,
    ));

    data.extend_from_slice(key_data);

    println!();
    println!("*************************************************************");
    println!("* WARNING! The following shares will NOT be stored anywhere *");
    println!("* Record them and store them safely if you wish to re-use   *");
    println!("* the wrap key for this device in the future                *");
    println!("*************************************************************");

    get_string("Press Enter to start recording key shares");

    let shares = rusty_secrets::generate_shares(threshold as u8, shares as u8, &data)
        .unwrap_or_else(|err| {
            println!("Unable to create shares: {}", err);
            std::process::exit(1);
        });

    for share in shares {
        loop {
            clear_screen();
            println!("{}", share);
            if Into::<bool>::into(get_boolean_answer("Have you recorded the key share?")) {
                break;
            }
        }
    }

    clear_screen();
}

fn recover_wrapkey() -> (
    u16,
    Vec<ObjectDomain>,
    Vec<ObjectCapability>,
    Vec<ObjectCapability>,
    Vec<u8>,
) {
    let shares = get_integer::<u16>("Enter the number of shares:", false);

    let mut shares_vec = Vec::new();

    while shares_vec.len() != shares as usize {
        let share = get_string(&*format!("Enter share number {}:", shares_vec.len() + 1));
        println!("Received share {}", share);

        if !SHARE_RE.is_match(&*share) {
            println!("Malformed share");
            continue;
        }

        shares_vec.push(share);
    }

    let secret = rusty_secrets::recover_secret(shares_vec).unwrap_or_else(|err| {
        println!("Unable to recover key: {}", err);
        std::process::exit(1);
    });

    // TODO(adma): magic numbers ...

    if secret.len() != 2 + 2 + 8 + 8 + WRAPKEY_LEN {
        println!(
            "Wrong length for recovered secret: expected {}, found {}",
            2 + 2 + 8 + 8 + WRAPKEY_LEN,
            secret.len()
        )
    }

    let wrap_id = ((u16::from(secret[0])) << 8) | u16::from(secret[1]);

    let domains = ObjectDomain::from_bytes(&secret[2..4]).unwrap_or_else(|err| {
        println!("Unable to parse domains: {}", err);
        std::process::exit(1);
    });

    let capabilities = ObjectCapability::from_bytes(&secret[4..12]).unwrap_or_else(|err| {
        println!("Unable to parse capabilities: {}", err);
        std::process::exit(1);
    });

    let delegated = ObjectCapability::from_bytes(&secret[12..20]).unwrap_or_else(|err| {
        println!("Unable to parse delegated capabilities: {}", err);
        std::process::exit(1);
    });

    let key = &secret[20..];

    (wrap_id, domains, capabilities, delegated, key.to_vec())
}

fn add_audit_key_maybe(
    session: &yubihsmrs::Session,
    wrap_id: u16,
    domains: &[yubihsmrs::object::ObjectDomain],
    export: bool,
) {
    if Into::<bool>::into(get_boolean_answer("Would you like to create an audit key?")) {
        let audit_id = get_integer("Enter audit key ID (0 to choose automatically):", true);
        let audit_password = get_string("Enter audit authentication key password:");

        // Create audit auth key
        let audit_id = session
            .import_authentication_key(
                audit_id,
                "Audit auth key",
                domains,
                &[
                    ObjectCapability::GetLogEntries,
                    ObjectCapability::ExportableUnderWrap,
                ],
                &[],
                audit_password.as_bytes(),
            )
            .unwrap_or_else(|err| {
                println!("Unable to import audit key: {}", err);
                std::process::exit(1);
            });
        println!(
            "Stored audit authentication key with ID 0x{:04x} on the device",
            audit_id
        );

        if export {
            let audit_wrapped = session
                .export_wrapped(wrap_id, ObjectType::AuthenticationKey, audit_id)
                .unwrap_or_else(|err| {
                    println!("Unable to export audit authentication key: {}", err);
                    std::process::exit(1);
                });

            let audit_file =
                object_to_file(audit_id, ObjectType::AuthenticationKey, &audit_wrapped)
                    .unwrap_or_else(|err| {
                        println!("Unable to save exported audit authentication key: {}", err);
                        std::process::exit(1);
                    });
            println!("Saved wrapped audit authentication key to {}\n", audit_file);
        }
    }
}

fn delete_previous_authkey_maybe(
    session: &yubihsmrs::Session,
    previous_auth_id: u16,
    delete: bool,
) {
    if delete {
        delete_object(session, previous_auth_id, ObjectType::AuthenticationKey);
        println!(
            "Previous authentication key 0x{:04x} deleted",
            previous_auth_id
        );
    } else {
        println!(
            "Previous authentication key 0x{:04x} *not* deleted. Make sure you know what you are doing",
            previous_auth_id
        );
    }
}

fn init_setup(
    session: &yubihsmrs::Session,
    previous_auth_id: u16,
    delete: bool,
    export: bool,
    wrapkey_delegated: &[ObjectCapability],
    authkey_capabilities: &[ObjectCapability],
    authkey_delegated: &[ObjectCapability],
) -> (u16, String) {
    let &wrapkey_capabilities = &[
        ObjectCapability::ImportWrapped,
        ObjectCapability::ExportWrapped,
    ];

    let wrapkey = session.get_random(WRAPKEY_LEN).unwrap_or_else(|err| {
        println!("Unable to generate random data: {}", err);
        std::process::exit(1);
    });

    let domains = get_domains("Enter domains:");

    // Create a wrapping key for importing application authentication keys and secrets
    let wrap_id = get_integer("Enter wrap key ID (0 to choose automatically):", true);
    let wrap_id = session
        .import_wrap_key(
            wrap_id,
            "Wrap key",
            &domains,
            &wrapkey_capabilities,
            ObjectAlgorithm::Aes256CcmWrap,
            &wrapkey_delegated,
            &wrapkey,
        )
        .unwrap_or_else(|err| {
            println!("Unable to import wrap key: {}", err);
            std::process::exit(1);
        });
    println!("Stored wrap key with ID 0x{:04x} on the device\n", wrap_id);

    // Split the wrap key
    let (threshold, shares) = get_threshold_and_shares();
    split_wrapkey(
        wrap_id,
        &domains,
        &wrapkey_capabilities,
        &wrapkey_delegated,
        &wrapkey,
        threshold,
        shares,
    );

    // Create an authentication key for usage with the above wrap key
    let auth_id = get_integer(
        "Enter application authentication key ID (0 to choose automatically):",
        true,
    );
    let application_password = get_string("Enter application authentication key password:");
    let auth_id = session
        .import_authentication_key(
            auth_id,
            "Application auth key",
            &domains,
            &authkey_capabilities,
            &authkey_delegated,
            application_password.as_bytes(),
        )
        .unwrap_or_else(|err| {
            println!("Unable to import application authentication key: {}", err);
            std::process::exit(1);
        });
    println!(
        "Stored application authentication key with ID 0x{:04x} on the device",
        auth_id
    );

    if export {
        let auth_wrapped = session
            .export_wrapped(wrap_id, ObjectType::AuthenticationKey, auth_id)
            .unwrap_or_else(|err| {
                println!("Unable to export application authentication key: {}", err);
                std::process::exit(1);
            });

        let auth_file = object_to_file(auth_id, ObjectType::AuthenticationKey, &auth_wrapped)
            .unwrap_or_else(|err| {
                println!(
                    "Unable to save exported application authentication key: {}",
                    err
                );
                std::process::exit(1);
            });

        println!(
            "Saved wrapped application authentication key to {}\n",
            auth_file
        );
    }

    add_audit_key_maybe(session, wrap_id, &domains, export);

    delete_previous_authkey_maybe(session, previous_auth_id, delete);

    (auth_id, application_password)
}

fn setup_ksp(session: &yubihsmrs::Session, previous_auth_id: u16, delete: bool, export: bool) {
    let capabilities_rsa_decrypt = &[ObjectCapability::DecryptPkcs, ObjectCapability::DecryptOaep];

    let mut wrapkey_delegated = vec![
        ObjectCapability::GenerateAsymmetricKey,
        ObjectCapability::SignPkcs,
        ObjectCapability::SignPss,
        ObjectCapability::ImportWrapped,
        ObjectCapability::ExportWrapped,
        ObjectCapability::ExportableUnderWrap,
        ObjectCapability::GetLogEntries,
    ];

    let mut authkey_capabilities = vec![
        ObjectCapability::GenerateAsymmetricKey,
        ObjectCapability::SignPkcs,
        ObjectCapability::SignPss,
        ObjectCapability::ImportWrapped,
        ObjectCapability::ExportWrapped,
        ObjectCapability::ExportableUnderWrap,
    ];

    let mut authkey_delegated = vec![
        ObjectCapability::GenerateAsymmetricKey,
        ObjectCapability::SignPkcs,
        ObjectCapability::SignPss,
        ObjectCapability::ExportableUnderWrap,
    ];

    if Into::<bool>::into(get_boolean_answer(
        "Would you like to add RSA decryption capabilities?",
    )) {
        wrapkey_delegated.extend_from_slice(capabilities_rsa_decrypt);
        authkey_capabilities.extend_from_slice(capabilities_rsa_decrypt);
        authkey_delegated.extend_from_slice(capabilities_rsa_decrypt);
    }

    init_setup(
        session,
        previous_auth_id,
        delete,
        export,
        &wrapkey_delegated,
        &authkey_capabilities,
        &authkey_delegated,
    );
}

fn parse_id(value: &str) -> Result<u16, String> {
    let id = if value.starts_with("0x") {
        u16::from_str_radix(&value[2..], 16)
    } else {
        value.parse::<u16>()
    };

    if id.is_ok() {
        let id = id.unwrap();
        if id != 0 {
            return Ok(id);
        }
    }

    Err("ID must be a number in [1, 65535]".to_string())
}

fn is_valid_id(value: String) -> Result<(), String> {
    // NOTE(adma): dropping value just to keep the linter quiet, the
    // prototype is dictated by Clap
    parse_id(&value).map(|_| {
        drop(value);
        ()
    })
}

fn reset_device(session: &yubihsmrs::Session, forced: bool) {
    if !forced
        && !Into::<bool>::into(get_boolean_answer(
            "This will erase the content of the device. Are you sure?",
        ))
    {
        println!("Reset aborted");
        return;
    }

    session.reset().unwrap_or_else(|err| {
        println!("Unable to reset device: {}", err);
        std::process::exit(1)
    });

    println!("Device successfully reset");
}

fn restore_device(session: &yubihsmrs::Session, previous_auth_id: u16, delete: bool) {
    let (wrap_id, domains, capabilities, delegated, key) = recover_wrapkey();

    let wrap_id = session
        .import_wrap_key(
            wrap_id,
            "Wrap key",
            &domains,
            &capabilities,
            ObjectAlgorithm::Aes256CcmWrap,
            &delegated,
            &key,
        )
        .unwrap_or_else(|err| {
            println!("Unable to import wrap key: {}", err);
            std::process::exit(1);
        });
    println!("Stored wrap key with ID 0x{:04x} on the device\n", wrap_id);

    let files: Vec<_> = ScanDir::files()
        .read(".", |iter| {
            iter.filter(|&(_, ref name)| name.ends_with(".yhw"))
                .map(|(entry, _)| entry.path())
                .collect()
        })
        .unwrap();

    for f in files {
        println!("reading {}", &f.display());
        let mut file = File::open(&f).unwrap_or_else(|err| {
            println!("Unable to import read file {}: {}", f.display(), err);
            std::process::exit(1);
        });

        let mut wrap = String::new();
        file.read_to_string(&mut wrap).unwrap_or_else(|err| {
            println!("Unable to read from file {}: {}", f.display(), err);
            std::process::exit(1);
        });

        let data = match base64::decode(&wrap) {
            Ok(decoded) => decoded,
            Err(err) => {
                println!(
                    "Unable to decode the content of file {}: {}. Skipping over ...",
                    f.display(),
                    err
                );
                continue;
            }
        };

        let handle = match session.import_wrapped(wrap_id, &data) {
            Ok(o) => o,
            Err(err) => {
                println!(
                    "Unable to import the content of file {}: {}. Skipping over ...",
                    f.display(),
                    err
                );
                continue;
            }
        };

        println!(
            "Successfully imported object {:?}, with ID 0x{:04x}",
            handle.object_type, handle.object_id
        );
    }

    delete_previous_authkey_maybe(session, previous_auth_id, delete);
}

fn dump_objects(session: &yubihsmrs::Session) {
    let wrap_id = get_integer(
        "Enter the wrapping key ID to use for exporting objects:",
        false,
    );

    let objects = session.list_objects().unwrap_or_else(|err| {
        println!("Unable to list objects: {}", err);
        std::process::exit(1);
    });

    println!("Found {} object(s)", objects.len());

    for object in objects {
        let wrap_result = session.export_wrapped(wrap_id, object.object_type, object.object_id);

        match wrap_result {
            Ok(bytes) => {
                let filename = object_to_file(object.object_id, object.object_type, &bytes)
                    .unwrap_or_else(|err| {
                        println!("Unable to save wrapped object: {}", err);
                        std::process::exit(1);
                    });

                println!(
                    "Successfully exported object {:?} with ID 0x{:04x} to {}",
                    object.object_type, object.object_id, filename
                );
            }
            Err(err) => println!(
                "Unable to export object {:?} with ID 0x{:04x}: {}. Skipping over ...",
                object.object_type, object.object_id, err
            ),
        }
    }
}

fn get_key_algorithm(prompt: &str) -> ObjectAlgorithm {
    let supported_algorithms = [
        ObjectAlgorithm::Rsa2048,
        ObjectAlgorithm::Rsa3072,
        ObjectAlgorithm::Rsa4096,
        ObjectAlgorithm::EcP224,
        ObjectAlgorithm::EcP256,
        ObjectAlgorithm::EcP384,
        ObjectAlgorithm::EcP521,
        ObjectAlgorithm::EcBp256,
        ObjectAlgorithm::EcBp384,
        ObjectAlgorithm::EcBp512,
        ObjectAlgorithm::EcK256,
    ];

    println!(
        "Supported asymmetric key algorithms: {:?}",
        supported_algorithms
    );

    let mut algo = get_string(prompt);
    loop {
        if let Ok(a) = algo.parse::<ObjectAlgorithm>() {
            break a;
        }

        println!("Unsupported algorithm. Please try again");
        algo = get_string(prompt);
    }
}

fn generate_keypair(
    session: &yubihsmrs::Session,
    label: &str,
    capabilities: &[ObjectCapability],
    domains: &[ObjectDomain],
    key_algorithm: ObjectAlgorithm,
) -> AsymmetricKey {
    let key = session
        .generate_asymmetric_key(&label, capabilities, domains, key_algorithm)
        .unwrap_or_else(|err| {
            println!("Unable to generate keypair: {}", err);
            std::process::exit(1);
        });

    key
}

fn import_certificate(
    session: &yubihsmrs::Session,
    key_id: u16,
    label: &str,
    domains: &[ObjectDomain],
    capabilities: &[ObjectCapability],
    cert: &[u8],
) -> u16 {
    let cert_object = session
        .import_opaque(
            key_id,
            &label,
            domains,
            capabilities,
            ObjectAlgorithm::OpaqueX509Certificate,
            cert,
        )
        .unwrap_or_else(|err| {
            println!("Unable to import certificate: {}", err);
            std::process::exit(1);
        });
    cert_object.get_id()
}

fn generate_selfsigned_certificate(session: &yubihsmrs::Session, key: AsymmetricKey) -> Vec<u8> {
    let selfsigned_certificate = key
        .sign_attestation_certificate(key.get_key_id(), session)
        .unwrap_or_else(|err| {
            println!("Unable to generate a self signed certificate: {}", err);
            std::process::exit(1);
        });
    selfsigned_certificate
}

fn init_ejbca_setup(
    session: &yubihsmrs::Session,
    previous_auth_id: u16,
    delete: bool,
    export: bool,
) -> (u16, String) {
    let capabilities = vec![
        ObjectCapability::GenerateAsymmetricKey,
        ObjectCapability::DeleteAsymmetricKey,
        ObjectCapability::PutOpaque,
        ObjectCapability::DeleteOpaque,
        ObjectCapability::GetOpaque,
        ObjectCapability::PutAuthenticationKey,
        ObjectCapability::DeleteAuthenticationKey,
        ObjectCapability::ImportWrapped,
        ObjectCapability::ExportWrapped,
        ObjectCapability::SignPkcs,
        ObjectCapability::SignPss,
        ObjectCapability::SignEcdsa,
        ObjectCapability::SignAttestationCertificate,
        ObjectCapability::ExportableUnderWrap,
    ];

    let mut delegated = vec![ObjectCapability::GetLogEntries];
    delegated.extend_from_slice(&capabilities);

    let (auth_id, password) = init_setup(
        session,
        previous_auth_id,
        delete,
        export,
        &delegated,
        &capabilities,
        &delegated,
    );
    (auth_id, password)
}

fn create_ejbca_asymm_key(session: &yubihsmrs::Session) {
    // Generate asymmetric keypair on the device
    let key_algorithm = get_key_algorithm("Enter asymmetric key algorithm:");
    let label = get_string("Enter key label:");
    let domains = get_domains("Enter domains:");

    let key_capabilities;
    if ObjectAlgorithm::is_rsa(key_algorithm) {
        key_capabilities = vec![
            ObjectCapability::SignPkcs,
            ObjectCapability::SignPss,
            ObjectCapability::SignAttestationCertificate,
            ObjectCapability::ExportableUnderWrap,
        ];
    } else {
        key_capabilities = vec![
            ObjectCapability::SignEcdsa,
            ObjectCapability::SignAttestationCertificate,
            ObjectCapability::ExportableUnderWrap,
        ];
    }

    let key = generate_keypair(session, &label, &key_capabilities, &domains, key_algorithm);
    let key_id = key.get_key_id();
    println!(
        "Generated asymmetric keypair with ID 0x{:04x} on the device",
        key_id
    );

    // Import attestation certificate template into the device
    let cert = base64::decode(EJBCA_ATTESTATION_TEMPLATE).unwrap();
    let cert_id = import_certificate(session, key_id, &label, &domains, &[], &cert);
    if cert_id != key_id {
        println!("Failed to store the attestation certificate template with the same ID as the asymmetric key");
        delete_object(session, key_id, ObjectType::AsymmetricKey);
        delete_object(session, cert_id, ObjectType::Opaque);
        std::process::exit(1);
    }

    // Generate self signed certificate for the asymmetric key
    let selfsigned_cert = generate_selfsigned_certificate(session, key);

    // Delete the attestation template certificate from the device
    delete_object(session, cert_id, ObjectType::Opaque);

    // Import the self signed certificate into the device
    let cert_id = import_certificate(
        session,
        key_id,
        &label,
        &domains,
        &[ObjectCapability::ExportableUnderWrap],
        &selfsigned_cert,
    );
    if cert_id != key_id {
        println!("Failed to store the attestation certificate template with the same ID as the asymmetric key");
        delete_object(session, key_id, ObjectType::AsymmetricKey);
        delete_object(session, cert_id, ObjectType::Opaque);
        std::process::exit(1);
    }
    println!(
        "Stored selfsigned certificate with ID 0x{:04x} on the device",
        cert_id
    );
}

fn setup_ejbca(
    h: &YubiHsm,
    session: &yubihsmrs::Session,
    previous_auth_id: u16,
    delete: bool,
    export: bool,
    create_new_authkey: bool,
) {
    let mut credentials = (previous_auth_id, String::new());
    if create_new_authkey {
        credentials = init_ejbca_setup(session, previous_auth_id, delete, export);
    }
    let auth_id = credentials.0;
    let password = credentials.1;

    if password.is_empty() {
        create_ejbca_asymm_key(session);
    } else {
        let new_session = h
            .establish_session(auth_id, &password, true)
            .unwrap_or_else(|err| {
                println!("Unable to open session: {}", err);
                std::process::exit(1);
            });
        create_ejbca_asymm_key(&new_session);
    }
}

fn main() {
    let matches = App::new(env!("CARGO_PKG_NAME"))
        .version(crate_version!())
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .setting(AppSettings::SubcommandRequired)
        .subcommands(vec![
            SubCommand::with_name("ksp").about("Setup for ADCS usage"),
            SubCommand::with_name("ejbca").about("Setup for EJBCA usage"),
            SubCommand::with_name("dump").about("Dump wrapped objects"),
            SubCommand::with_name("restore").about("Restore or setup additional devices"),
            SubCommand::with_name("reset")
                .about("Reset the device")
                .arg(
                    Arg::with_name("force")
                        .long("force")
                        .short("f")
                        .help("Do not ask for confirmation during reset"),
                ),
        ]).arg(
            Arg::with_name("authkey")
                .long("authkey")
                .short("k")
                .help("Authentication key to open a session with the device")
                .default_value("1")
                .takes_value(true)
                .hide_default_value(false)
                .validator(is_valid_id),
        ).arg(
            Arg::with_name("password")
                .long("password")
                .short("p")
                .help("Password to open a session with the device")
                .takes_value(true),
        ).arg(
            Arg::with_name("connector")
                .long("connector")
                .short("c")
                .help("Connector URL")
                .default_value("http://127.0.0.1:12345")
                .takes_value(true)
                .hide_default_value(false),
        ).arg(
            Arg::with_name("no-delete")
                .long("no-delete")
                .short("d")
                .help("Do not delete the authentication key when done"),
        ).arg(
            Arg::with_name("no-export")
                .long("no-export")
                .short("e")
                .help("Do not export under wrap the application objects"), // TODO(adma): should this also drop capabilities?
        ).arg(
            Arg::with_name("no-new-authkey")
                .long("no-new-authkey")
                .short("a")
                .help("Use this flag if you want to generate an asymmetric key and self-signed certificate on the YubiHSM for use with EJBCA"),

        ).arg(
            Arg::with_name("verbose")
                .long("verbose")
                .short("v")
                .help("Produce more debug output"),
        ).get_matches();

    let connector = matches.value_of("connector").unwrap();
    let authkey = parse_id(matches.value_of("authkey").unwrap()).unwrap();
    let password = match matches.value_of("password") {
        Some(password) => password.to_owned(),
        None => get_string("Enter authentication password:"),
    };

    yubihsmrs::init().unwrap_or_else(|err| {
        println!("Unable to initialize libyubihsm: {}", err);
        std::process::exit(1);
    });

    let h = YubiHsm::new(connector).unwrap_or_else(|err| {
        println!("Unable to create HSM object: {}", err);
        std::process::exit(1);
    });

    h.set_verbosity(matches.is_present("verbose"))
        .unwrap_or_else(|err| {
            println!("Unable to set verbosity: {}", err);
            std::process::exit(1);
        });

    println!("Using authentication key 0x{:04x}", authkey);

    let session = h
        .establish_session(authkey, &password, true)
        .unwrap_or_else(|err| {
            println!("Unable to open session: {}", err);
            std::process::exit(1);
        });

    match matches.subcommand_name() {
        Some("ksp") => setup_ksp(
            &session,
            authkey,
            !matches.is_present("no-delete"),
            !matches.is_present("no-export"),
        ),
        Some("ejbca") => setup_ejbca(
            &h,
            &session,
            authkey,
            !matches.is_present("no-delete"),
            !matches.is_present("no-export"),
            !matches.is_present("no-new-authkey"),
        ),
        Some("dump") => dump_objects(&session),
        Some("reset") => reset_device(
            &session,
            matches
                .subcommand_matches("reset")
                .unwrap()
                .is_present("force"),
        ),
        Some("restore") => restore_device(&session, authkey, !matches.is_present("no-delete")),
        _ => unreachable!(),
    }

    println!("All done")
}
