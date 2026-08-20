#![forbid(unsafe_code)]

use std::{
    collections::HashMap,
    io::{self, Read},
    sync::RwLock,
};

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_memory_storage::MemoryStorage;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::OpenMlsProvider;
use serde::{Deserialize, Serialize};
use tls_codec::{DeserializeBytes, Serialize as TlsSerialize};

const SCHEMA: &str = "tos.openmls.sidecar.v1";
const SUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
const MAX_REQUEST: u64 = 4 * 1024 * 1024;
const MAX_STATE: usize = 512 * 1024;
const MAX_ENTRIES: usize = 4096;
const MAX_KEY: usize = 64 * 1024;
const MAX_VALUE: usize = 512 * 1024;
const MAX_IDENTITY: usize = 4096;
const MAX_MESSAGE: usize = 1024 * 1024;

#[derive(Default)]
struct Provider {
    crypto: RustCrypto,
    storage: MemoryStorage,
}

impl OpenMlsProvider for Provider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = MemoryStorage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }
    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }
    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    op: String,
    #[serde(default)]
    state: String,
    #[serde(default)]
    identity: String,
    #[serde(default)]
    public_key: String,
    #[serde(default)]
    group_id: String,
    #[serde(default)]
    key_package: String,
    #[serde(default)]
    key_packages: Vec<String>,
    #[serde(default)]
    remove_identities: Vec<String>,
    #[serde(default)]
    welcome: String,
    #[serde(default)]
    message: String,
    #[serde(default)]
    aad: String,
    #[serde(default)]
    plaintext: String,
    #[serde(default)]
    label: String,
    #[serde(default)]
    context: String,
    #[serde(default)]
    length: u16,
}

#[derive(Default, Serialize)]
struct Response {
    schema: &'static str,
    ok: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    error: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    state: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    public_key: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    key_package: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    commit: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    welcome: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    message: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    plaintext: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    group_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    secret: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    epoch: Option<u64>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    schema: String,
    signer_public: String,
    #[serde(default)]
    group_id: String,
    entries: Vec<Entry>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    key: String,
    value: String,
}

fn decode(label: &str, value: &str, max: usize) -> Result<Vec<u8>, String> {
    let bytes = B64
        .decode(value)
        .map_err(|_| format!("invalid {label} encoding"))?;
    if bytes.is_empty() || bytes.len() > max {
        return Err(format!("invalid {label} length"));
    }
    Ok(bytes)
}

fn encode<T: TlsSerialize>(value: &T) -> Result<String, String> {
    value
        .tls_serialize_detached()
        .map(|v| B64.encode(v))
        .map_err(|_| "MLS serialization failed".into())
}

fn decode_tls<T: DeserializeBytes>(label: &str, value: &str, max: usize) -> Result<T, String> {
    let bytes = decode(label, value, max)?;
    let (parsed, rest) =
        T::tls_deserialize_bytes(&bytes).map_err(|_| format!("invalid {label}"))?;
    if !rest.is_empty() {
        return Err(format!("trailing {label} bytes"));
    }
    Ok(parsed)
}

fn load_snapshot(encoded: &str) -> Result<(Provider, Snapshot), String> {
    let raw = decode("state", encoded, MAX_STATE)?;
    let snapshot: Snapshot =
        serde_json::from_slice(&raw).map_err(|_| "invalid state snapshot".to_string())?;
    if snapshot.schema != SCHEMA || snapshot.entries.len() > MAX_ENTRIES {
        return Err("unsupported state snapshot".into());
    }
    let signer = decode("signer public key", &snapshot.signer_public, 64)?;
    if signer.len() != 32 {
        return Err("invalid signer public key".into());
    }
    let mut values = HashMap::with_capacity(snapshot.entries.len());
    let mut total = 0usize;
    for entry in &snapshot.entries {
        let key = decode("state key", &entry.key, MAX_KEY)?;
        let value = decode("state value", &entry.value, MAX_VALUE)?;
        total = total
            .checked_add(key.len() + value.len())
            .ok_or("state size overflow")?;
        if total > MAX_STATE || values.insert(key, value).is_some() {
            return Err("invalid state entries".into());
        }
    }
    Ok((
        Provider {
            crypto: RustCrypto::default(),
            storage: MemoryStorage {
                values: RwLock::new(values),
            },
        },
        snapshot,
    ))
}

fn save_snapshot(
    provider: &Provider,
    signer_public: &[u8],
    group_id: Option<&GroupId>,
) -> Result<String, String> {
    let values = provider
        .storage
        .values
        .read()
        .map_err(|_| "state lock poisoned")?;
    if values.len() > MAX_ENTRIES {
        return Err("state has too many entries".into());
    }
    let mut pairs: Vec<_> = values.iter().collect();
    pairs.sort_by(|a, b| a.0.cmp(b.0));
    let entries = pairs
        .into_iter()
        .map(|(key, value)| Entry {
            key: B64.encode(key),
            value: B64.encode(value),
        })
        .collect();
    let snapshot = Snapshot {
        schema: SCHEMA.into(),
        signer_public: B64.encode(signer_public),
        group_id: group_id
            .map(|g| B64.encode(g.as_slice()))
            .unwrap_or_default(),
        entries,
    };
    let raw = serde_json::to_vec(&snapshot).map_err(|_| "state serialization failed")?;
    if raw.len() > MAX_STATE {
        return Err("state snapshot exceeds bound".into());
    }
    Ok(B64.encode(raw))
}

fn signer(provider: &Provider, snapshot: &Snapshot) -> Result<SignatureKeyPair, String> {
    let public = decode("signer public key", &snapshot.signer_public, 64)?;
    SignatureKeyPair::read(provider.storage(), &public, SUITE.signature_algorithm())
        .ok_or("missing signer key".into())
}

fn group(provider: &Provider, snapshot: &Snapshot) -> Result<MlsGroup, String> {
    let id = decode("group id", &snapshot.group_id, 255)?;
    MlsGroup::load(provider.storage(), &GroupId::from_slice(&id))
        .map_err(|_| "group state load failed".to_string())?
        .ok_or("missing group state".into())
}

fn handle(req: Request) -> Result<Response, String> {
    if req.schema != SCHEMA {
        return Err("unsupported request schema".into());
    }
    let mut out = Response {
        schema: SCHEMA,
        ok: true,
        ..Default::default()
    };
    match req.op.as_str() {
        "inspect" => {
            let (provider, snapshot) = load_snapshot(&req.state)?;
            let group = group(&provider, &snapshot)?;
            out.group_id = B64.encode(group.group_id().as_slice());
            out.epoch = Some(group.epoch().as_u64());
        }
        "export" => {
            if req.label.is_empty() || req.label.len() > 255 || req.length == 0 {
                return Err("invalid exporter request".into());
            }
            let context = if req.context.is_empty() {
                Vec::new()
            } else {
                decode("exporter context", &req.context, 4096)?
            };
            let (provider, snapshot) = load_snapshot(&req.state)?;
            let group = group(&provider, &snapshot)?;
            let secret = group
                .export_secret(provider.crypto(), &req.label, &context, req.length as usize)
                .map_err(|_| "secret export failed")?;
            out.secret = B64.encode(secret);
            out.group_id = B64.encode(group.group_id().as_slice());
            out.epoch = Some(group.epoch().as_u64());
        }
        "validate" => {
            let expected_identity = decode("identity", &req.identity, MAX_IDENTITY)?;
            let expected_public = decode("public key", &req.public_key, 64)?;
            if expected_public.len() != 32 {
                return Err("invalid public key length".into());
            }
            let provider = Provider::default();
            let package = decode_tls::<KeyPackageIn>("key package", &req.key_package, 64 * 1024)?
                .validate(provider.crypto(), ProtocolVersion::Mls10)
                .map_err(|_| "invalid KeyPackage")?;
            if package.ciphersuite() != SUITE
                || package.leaf_node().credential().credential_type() != CredentialType::Basic
            {
                return Err("unsupported KeyPackage profile".into());
            }
            if package.leaf_node().credential().serialized_content() != expected_identity
                || package.leaf_node().signature_key().as_slice() != expected_public
            {
                return Err("KeyPackage authority mismatch".into());
            }
        }
        "identity" => {
            let identity = decode("identity", &req.identity, MAX_IDENTITY)?;
            let provider = Provider::default();
            let signer = SignatureKeyPair::new(SUITE.signature_algorithm())
                .map_err(|_| "signer generation failed")?;
            signer
                .store(provider.storage())
                .map_err(|_| "signer storage failed")?;
            let credential = CredentialWithKey {
                credential: BasicCredential::new(identity).into(),
                signature_key: signer.to_public_vec().into(),
            };
            let bundle = KeyPackage::builder()
                .build(SUITE, &provider, &signer, credential)
                .map_err(|_| "KeyPackage generation failed")?;
            out.public_key = B64.encode(signer.public());
            out.key_package = encode(bundle.key_package())?;
            out.state = save_snapshot(&provider, signer.public(), None)?;
        }
        "create" => {
            let (provider, snapshot) = load_snapshot(&req.state)?;
            if !snapshot.group_id.is_empty() {
                return Err("identity already belongs to a group".into());
            }
            let signer = signer(&provider, &snapshot)?;
            let identity = decode_tls::<KeyPackageIn>("key package", &req.key_package, 64 * 1024)?
                .validate(provider.crypto(), ProtocolVersion::Mls10)
                .map_err(|_| "invalid own KeyPackage")?;
            if identity.ciphersuite() != SUITE
                || identity.leaf_node().credential().credential_type() != CredentialType::Basic
                || identity.leaf_node().signature_key().as_slice() != signer.public()
            {
                return Err("own KeyPackage does not match signer".into());
            }
            let credential = CredentialWithKey {
                credential: identity.leaf_node().credential().clone(),
                signature_key: signer.to_public_vec().into(),
            };
            let group_id = decode("group id", &req.group_id, 255)?;
            let config = MlsGroupCreateConfig::builder()
                .ciphersuite(SUITE)
                .use_ratchet_tree_extension(true)
                .build();
            let group = MlsGroup::new_with_group_id(
                &provider,
                &signer,
                &config,
                GroupId::from_slice(&group_id),
                credential,
            )
            .map_err(|_| "group creation failed")?;
            out.epoch = Some(group.epoch().as_u64());
            out.state = save_snapshot(&provider, signer.public(), Some(group.group_id()))?;
        }
        "commit" => {
            if req.key_packages.len() + req.remove_identities.len() == 0
                || req.key_packages.len() + req.remove_identities.len() > 64
            {
                return Err("invalid member count".into());
            }
            let (provider, snapshot) = load_snapshot(&req.state)?;
            let signer = signer(&provider, &snapshot)?;
            let mut group = group(&provider, &snapshot)?;
            let mut packages = Vec::with_capacity(req.key_packages.len());
            for value in &req.key_packages {
                let package = decode_tls::<KeyPackageIn>("key package", value, 64 * 1024)?
                    .validate(provider.crypto(), ProtocolVersion::Mls10)
                    .map_err(|_| "invalid KeyPackage")?;
                if package.ciphersuite() != SUITE
                    || package.leaf_node().credential().credential_type() != CredentialType::Basic
                {
                    return Err("unsupported KeyPackage profile".into());
                }
                packages.push(package);
            }
            let mut removals = Vec::with_capacity(req.remove_identities.len());
            for value in &req.remove_identities {
                let identity = decode("removed identity", value, MAX_IDENTITY)?;
                let matches: Vec<_> = group
                    .members()
                    .filter(|member| member.credential.serialized_content() == identity)
                    .map(|member| member.index)
                    .collect();
                if matches.len() != 1 {
                    return Err("removed identity is absent or ambiguous".into());
                }
                if removals.contains(&matches[0]) {
                    return Err("duplicate removed identity".into());
                }
                removals.push(matches[0]);
            }
            let bundle = group
                .commit_builder()
                .propose_removals(removals)
                .propose_adds(packages)
                .load_psks(provider.storage())
                .map_err(|_| "commit PSK load failed")?
                .build(provider.rand(), provider.crypto(), &signer, |_| true)
                .map_err(|_| "commit creation failed")?
                .stage_commit(&provider)
                .map_err(|_| "commit staging failed")?;
            group
                .merge_pending_commit(&provider)
                .map_err(|_| "commit merge failed")?;
            let (commit, welcome, _) = bundle.into_messages();
            out.commit = encode(&commit)?;
            if let Some(welcome) = welcome {
                out.welcome = encode(&welcome)?;
            }
            out.epoch = Some(group.epoch().as_u64());
            out.state = save_snapshot(&provider, signer.public(), Some(group.group_id()))?;
        }
        "refresh" => {
            let (provider, snapshot) = load_snapshot(&req.state)?;
            let signer = signer(&provider, &snapshot)?;
            let mut group = group(&provider, &snapshot)?;
            let bundle = group
                .self_update(&provider, &signer, LeafNodeParameters::default())
                .map_err(|_| "self update failed")?;
            group
                .merge_pending_commit(&provider)
                .map_err(|_| "self update merge failed")?;
            out.commit = encode(&bundle.into_commit())?;
            out.epoch = Some(group.epoch().as_u64());
            out.state = save_snapshot(&provider, signer.public(), Some(group.group_id()))?;
        }
        "join" => {
            let (provider, snapshot) = load_snapshot(&req.state)?;
            if !snapshot.group_id.is_empty() {
                return Err("identity already belongs to a group".into());
            }
            let welcome: MlsMessageIn = decode_tls("welcome", &req.welcome, MAX_MESSAGE)?;
            let welcome = match welcome.extract() {
                MlsMessageBodyIn::Welcome(v) => v,
                _ => return Err("message is not a Welcome".into()),
            };
            let config = MlsGroupJoinConfig::builder()
                .use_ratchet_tree_extension(true)
                .build();
            let group = StagedWelcome::new_from_welcome(&provider, &config, welcome, None)
                .map_err(|_| "Welcome processing failed")?
                .into_group(&provider)
                .map_err(|_| "Welcome merge failed")?;
            let public = decode("signer public key", &snapshot.signer_public, 64)?;
            out.epoch = Some(group.epoch().as_u64());
            out.state = save_snapshot(&provider, &public, Some(group.group_id()))?;
        }
        "apply" => {
            let (provider, snapshot) = load_snapshot(&req.state)?;
            let mut group = group(&provider, &snapshot)?;
            let message: MlsMessageIn = decode_tls("commit", &req.message, MAX_MESSAGE)?;
            let processed = group
                .process_message(
                    &provider,
                    message
                        .try_into_protocol_message()
                        .map_err(|_| "message is not an MLS protocol message")?,
                )
                .map_err(|_| "commit processing failed")?;
            let staged = match processed.into_content() {
                ProcessedMessageContent::StagedCommitMessage(v) => v,
                _ => return Err("message is not a commit".into()),
            };
            group
                .merge_staged_commit(&provider, *staged)
                .map_err(|_| "commit merge failed")?;
            let public = decode("signer public key", &snapshot.signer_public, 64)?;
            out.epoch = Some(group.epoch().as_u64());
            out.state = save_snapshot(&provider, &public, Some(group.group_id()))?;
        }
        "seal" => {
            let (provider, snapshot) = load_snapshot(&req.state)?;
            let signer = signer(&provider, &snapshot)?;
            let mut group = group(&provider, &snapshot)?;
            let aad = if req.aad.is_empty() {
                Vec::new()
            } else {
                decode("aad", &req.aad, 64 * 1024)?
            };
            let plaintext = decode("plaintext", &req.plaintext, MAX_MESSAGE)?;
            group.set_aad(aad);
            let message = group
                .create_message(&provider, &signer, &plaintext)
                .map_err(|_| "message encryption failed")?;
            out.message = encode(&message)?;
            out.epoch = Some(group.epoch().as_u64());
            out.state = save_snapshot(&provider, signer.public(), Some(group.group_id()))?;
        }
        "open" => {
            let (provider, snapshot) = load_snapshot(&req.state)?;
            let mut group = group(&provider, &snapshot)?;
            let aad = if req.aad.is_empty() {
                Vec::new()
            } else {
                decode("aad", &req.aad, 64 * 1024)?
            };
            let message: MlsMessageIn = decode_tls("message", &req.message, MAX_MESSAGE)?;
            let protocol = message
                .try_into_protocol_message()
                .map_err(|_| "message is not an MLS protocol message")?;
            match &protocol {
                ProtocolMessage::PrivateMessage(value) if value.aad() == aad => {}
                ProtocolMessage::PrivateMessage(_) => {
                    return Err("authenticated data mismatch".into())
                }
                _ => return Err("application message is not private".into()),
            }
            let processed = group
                .process_message(&provider, protocol)
                .map_err(|_| "message decryption failed")?;
            let plaintext = match processed.into_content() {
                ProcessedMessageContent::ApplicationMessage(v) => v.into_bytes(),
                _ => return Err("message is not application data".into()),
            };
            let public = decode("signer public key", &snapshot.signer_public, 64)?;
            out.plaintext = B64.encode(plaintext);
            out.epoch = Some(group.epoch().as_u64());
            out.state = save_snapshot(&provider, &public, Some(group.group_id()))?;
        }
        _ => return Err("unsupported operation".into()),
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(op: &str) -> Request {
        Request {
            schema: SCHEMA.into(),
            op: op.into(),
            state: String::new(),
            identity: String::new(),
            public_key: String::new(),
            group_id: String::new(),
            key_package: String::new(),
            key_packages: vec![],
            remove_identities: vec![],
            welcome: String::new(),
            message: String::new(),
            aad: String::new(),
            plaintext: String::new(),
            label: String::new(),
            context: String::new(),
            length: 0,
        }
    }

    fn identity(name: &[u8]) -> Response {
        let mut req = request("identity");
        req.identity = B64.encode(name);
        handle(req).unwrap()
    }

    #[test]
    fn three_members_chat_after_snapshot_restart() {
        let alice = identity(b"alice-authority");
        let bob = identity(b"bob-authority");
        let charlie = identity(b"charlie-authority");

        let mut validate = request("validate");
        validate.identity = B64.encode(b"bob-authority");
        validate.public_key = bob.public_key.clone();
        validate.key_package = bob.key_package.clone();
        handle(validate).unwrap();

        let mut create = request("create");
        create.state = alice.state;
        create.key_package = alice.key_package;
        create.group_id = B64.encode(b"0123456789abcdef0123456789abcdef");
        let founder = handle(create).unwrap();

        let mut add = request("commit");
        add.state = founder.state;
        add.key_packages = vec![bob.key_package, charlie.key_package];
        let added = handle(add).unwrap();
        assert_eq!(added.epoch, Some(1));

        let mut bob_join = request("join");
        bob_join.state = bob.state;
        bob_join.welcome = added.welcome.clone();
        let bob_joined = handle(bob_join).unwrap();

        let mut charlie_join = request("join");
        charlie_join.state = charlie.state;
        charlie_join.welcome = added.welcome;
        let charlie_joined = handle(charlie_join).unwrap();

        // Each operation reconstructs a fresh provider exclusively from the
        // returned snapshot, so this is also a process-restart proof.
        let mut seal = request("seal");
        seal.state = bob_joined.state;
        seal.aad = B64.encode(b"room+event binding");
        seal.plaintext = B64.encode(b"hello encrypted group");
        let sealed = handle(seal).unwrap();

        let mut open = request("open");
        open.state = charlie_joined.state;
        open.aad = B64.encode(b"room+event binding");
        open.message = sealed.message.clone();
        let opened = handle(open).unwrap();
        assert_eq!(
            B64.decode(opened.plaintext).unwrap(),
            b"hello encrypted group"
        );

        let mut wrong_aad = request("open");
        wrong_aad.state = added.state;
        wrong_aad.aad = B64.encode(b"different event");
        wrong_aad.message = sealed.message;
        assert!(handle(wrong_aad).is_err());
    }

    #[test]
    fn rejects_authority_substitution_and_corrupt_snapshot() {
        let member = identity(b"member-one");
        let mut validate = request("validate");
        validate.identity = B64.encode(b"member-two");
        validate.public_key = member.public_key;
        validate.key_package = member.key_package;
        assert!(handle(validate).is_err());

        let mut corrupt = request("create");
        corrupt.state = B64
            .encode(br#"{"schema":"tos.openmls.sidecar.v1","signer_public":"AA==","entries":[]}"#);
        corrupt.key_package = B64.encode(b"not a key package");
        corrupt.group_id = B64.encode(b"group");
        assert!(handle(corrupt).is_err());
    }
}

fn main() {
    let mut raw = Vec::new();
    let result = io::stdin()
        .take(MAX_REQUEST + 1)
        .read_to_end(&mut raw)
        .map_err(|_| "request read failed".to_string())
        .and_then(|_| {
            if raw.len() as u64 > MAX_REQUEST {
                Err("request exceeds bound".into())
            } else {
                serde_json::from_slice::<Request>(&raw).map_err(|_| "invalid request".into())
            }
        })
        .and_then(handle);
    let response = match result {
        Ok(v) => v,
        Err(error) => Response {
            schema: SCHEMA,
            ok: false,
            error,
            ..Default::default()
        },
    };
    if serde_json::to_writer(io::stdout(), &response).is_err() {
        std::process::exit(2);
    }
    if !response.ok {
        std::process::exit(1);
    }
}
