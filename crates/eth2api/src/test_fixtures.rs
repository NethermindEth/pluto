#![allow(missing_docs)]

use crate::spec::{altair, bellatrix, capella, deneb, electra, phase0};
use pluto_ssz::{BitList, BitVector};
use serde_json::Value;
use tree_hash::TreeHash;

const PHASE0_DEPOSIT_ROOT: &str =
    "ba363a243ab8a0e098fdd1b051d07fb3f99ee0884bbf8d560bb18fbdbe7657e2";
const BELLATRIX_EXECUTION_PAYLOAD_ROOT: &str =
    "a696658f3f218abf3acf2cbc38ff7f1a908dc4cbf73c3e12f56bb8ac29f55b82";
const BELLATRIX_EXECUTION_PAYLOAD_HEADER_ROOT: &str =
    "756e9a12068b2f035fb3ffb640d882e47389ce714ac68c270d52c107bdc2f56a";
const CAPELLA_EXECUTION_PAYLOAD_ROOT: &str =
    "62634b94221e88a5f88688d871e9074ca12417028446bba3098e4b1acd4892c1";
const CAPELLA_EXECUTION_PAYLOAD_HEADER_ROOT: &str =
    "15f582233cd0d75c974e3967102b44b4f710d0c94d5f7a71e3771aa2cdb8cd8f";
const DENEB_EXECUTION_PAYLOAD_ROOT: &str =
    "72fefabd13399ff66c236da2690074fa16d310db180011ebcdc705c77082c8f3";
const DENEB_EXECUTION_PAYLOAD_HEADER_ROOT: &str =
    "7744a180cb9373a6275ac2e0d9f3253df175affb72052a9142b26efc46e74f33";

const PHASE0_BEACON_BLOCK_BODY_ROOT: &str =
    "cd430e3209addd8fa3c61b266ee2aa9a94f39cf6856bc99daeb5f163c385b421";
const PHASE0_BEACON_BLOCK_ROOT: &str =
    "454b60c18588577712bbba2446d8d77f841910b67d29af89bd36bd8828e82c79";
const ALTAIR_BEACON_BLOCK_BODY_ROOT: &str =
    "560e5b45f3fd6f0e3a546194c75815f9eb5d07518b03581b963c810bdca666a7";
const ALTAIR_BEACON_BLOCK_ROOT: &str =
    "deca1dca101bff194d5dbf5d8efafc14f76fab63e7a3c1a64650949bc1a09aed";
const BELLATRIX_BEACON_BLOCK_BODY_ROOT: &str =
    "01189b4bcd92001bf3c68d530a521a95faaa0f21caf881068d269881baaf23b4";
const BELLATRIX_BEACON_BLOCK_ROOT: &str =
    "8af701ff184d5b46478707dea1a085542e042fcf46683a2fcf0e065e19f1a009";
const CAPELLA_BEACON_BLOCK_BODY_ROOT: &str =
    "ee0895a2df761fadeb29444e4cd3d5f1a0e3f88e42df6928711bd6bd07612a60";
const CAPELLA_BEACON_BLOCK_ROOT: &str =
    "983f5e3b7bd75af488e9ce91b904ca62abb46c9e9f1e00b0ec73d823d85fed44";
const DENEB_BEACON_BLOCK_BODY_ROOT: &str =
    "2a72ce02058ed43efeb58ec29b899f3ff3a07abc88c7b7f712c2622db9fae52d";
const DENEB_BEACON_BLOCK_ROOT: &str =
    "e8df49b1bb3fa3e9ffcf66c6b574856cbea301aeeac239e9265ae821296c8807";
const ELECTRA_BEACON_BLOCK_BODY_ROOT: &str =
    "c6d313b39d87c588a2a10b88f4f3c33c79254b8b8c96185d008c9ed233a1cd08";
const ELECTRA_BEACON_BLOCK_ROOT: &str =
    "8793985ba0dcf366be535ab1e2298462085620ede9b7a351f77b79b6d442f57f";
const FULU_BEACON_BLOCK_BODY_ROOT: &str = ELECTRA_BEACON_BLOCK_BODY_ROOT;
const FULU_BEACON_BLOCK_ROOT: &str = ELECTRA_BEACON_BLOCK_ROOT;

const BELLATRIX_EXECUTION_PAYLOAD_JSON: &str = r#"{"parent_hash":"0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","fee_recipient":"0x1112131415161718191A1b1C1D1E1f2021222324","state_root":"0x2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40","receipts_root":"0x3132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f50","logs_bloom":"0x4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40","prev_randao":"0x5152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f70","block_number":"12345","gas_limit":"30000000","gas_used":"12345678","timestamp":"1700000000","extra_data":"0xaabbcc","base_fee_per_gas":"123456789","block_hash":"0x6162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80","transactions":["0xdead","0xbeef01"]}"#;
const BELLATRIX_EXECUTION_PAYLOAD_HEADER_JSON: &str = r#"{"parent_hash":"0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","fee_recipient":"0x1112131415161718191A1b1C1D1E1f2021222324","state_root":"0x2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40","receipts_root":"0x3132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f50","logs_bloom":"0x4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40","prev_randao":"0x5152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f70","block_number":"12345","gas_limit":"30000000","gas_used":"12345678","timestamp":"1700000000","extra_data":"0xaabbcc","base_fee_per_gas":"123456789","block_hash":"0x6162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80","transactions_root":"0x7172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f90"}"#;
const CAPELLA_EXECUTION_PAYLOAD_JSON: &str = r#"{"parent_hash":"0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","fee_recipient":"0x1112131415161718191A1b1C1D1E1f2021222324","state_root":"0x2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40","receipts_root":"0x3132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f50","logs_bloom":"0x4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40","prev_randao":"0x5152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f70","block_number":"22222","gas_limit":"31000000","gas_used":"10000000","timestamp":"1700000123","extra_data":"0x01020304","base_fee_per_gas":"987654321","block_hash":"0x8182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0","transactions":["0xabcdef"],"withdrawals":[{"index":"1","validator_index":"2","address":"0x9192939495969798999a9b9c9d9e9fa0a1a2a3a4","amount":"3333333333"}]}"#;
const CAPELLA_EXECUTION_PAYLOAD_HEADER_JSON: &str = r#"{"parent_hash":"0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","fee_recipient":"0x1112131415161718191A1b1C1D1E1f2021222324","state_root":"0x2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40","receipts_root":"0x3132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f50","logs_bloom":"0x4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40","prev_randao":"0x5152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f70","block_number":"22222","gas_limit":"31000000","gas_used":"10000000","timestamp":"1700000123","extra_data":"0x01020304","base_fee_per_gas":"987654321","block_hash":"0x8182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0","transactions_root":"0xa1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0","withdrawals_root":"0xa2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1"}"#;
const DENEB_EXECUTION_PAYLOAD_JSON: &str = r#"{"parent_hash":"0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","fee_recipient":"0x1112131415161718191A1b1C1D1E1f2021222324","state_root":"0x2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40","receipts_root":"0x3132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f50","logs_bloom":"0x4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40","prev_randao":"0x5152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f70","block_number":"33333","gas_limit":"32000000","gas_used":"8888888","timestamp":"1700000456","extra_data":"0x0a0b","base_fee_per_gas":"42","block_hash":"0xb1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0","transactions":["0x01","0x0203"],"withdrawals":[{"index":"9","validator_index":"10","address":"0xb2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5","amount":"4444"}],"blob_gas_used":"777","excess_blob_gas":"888"}"#;
const DENEB_EXECUTION_PAYLOAD_HEADER_JSON: &str = r#"{"parent_hash":"0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","fee_recipient":"0x1112131415161718191A1b1C1D1E1f2021222324","state_root":"0x2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40","receipts_root":"0x3132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f50","logs_bloom":"0x4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40","prev_randao":"0x5152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f70","block_number":"33333","gas_limit":"32000000","gas_used":"8888888","timestamp":"1700000456","extra_data":"0x0a0b","base_fee_per_gas":"42","block_hash":"0xb1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0","transactions_root":"0xc1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0","withdrawals_root":"0xc2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1","blob_gas_used":"777","excess_blob_gas":"888"}"#;
const V1_VALIDATOR_REGISTRATION_JSON: &str = r#"{"fee_recipient":"0xd1d2d3D4D5d6D7d8d9dAdbDCDDdEDFE0E1E2E3e4","gas_limit":"30000000","timestamp":"1700000789","pubkey":"0xd2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff0001"}"#;
const V1_BEACON_COMMITTEE_SELECTION_JSON: &str = r#"{"validator_index":"55","slot":"66","selection_proof":"0xd3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132"}"#;
const V1_SYNC_COMMITTEE_SELECTION_JSON: &str = r#"{"validator_index":"77","slot":"88","subcommittee_index":"99","selection_proof":"0xd4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30313233"}"#;
const DENEB_KZG_COMMITMENT_JSON: &str = r#""0xe1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f10""#;
const ELECTRA_OVERSIZED_ATTESTATION_JSON: &str = r#"{"aggregation_bits":"0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006","data":{"slot":"11","index":"7","beacon_block_root":"0xa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf","source":{"epoch":"3","root":"0xb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf"},"target":{"epoch":"4","root":"0xc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf"}},"signature":"0xe2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041","committee_bits":"0x0800000000000000"}"#;

#[derive(Clone, Copy)]
pub(crate) struct Vectors {
    pub phase0_deposit_root: &'static str,
    pub bellatrix_execution_payload_root: &'static str,
    pub bellatrix_execution_payload_header_root: &'static str,
    pub capella_execution_payload_root: &'static str,
    pub capella_execution_payload_header_root: &'static str,
    pub deneb_execution_payload_root: &'static str,
    pub deneb_execution_payload_header_root: &'static str,
    pub phase0_beacon_block_body_root: &'static str,
    pub phase0_beacon_block_root: &'static str,
    pub altair_beacon_block_body_root: &'static str,
    pub altair_beacon_block_root: &'static str,
    pub bellatrix_beacon_block_body_root: &'static str,
    pub bellatrix_beacon_block_root: &'static str,
    pub capella_beacon_block_body_root: &'static str,
    pub capella_beacon_block_root: &'static str,
    pub deneb_beacon_block_body_root: &'static str,
    pub deneb_beacon_block_root: &'static str,
    pub electra_beacon_block_body_root: &'static str,
    pub electra_beacon_block_root: &'static str,
    pub fulu_beacon_block_body_root: &'static str,
    pub fulu_beacon_block_root: &'static str,
    pub bellatrix_execution_payload_json: &'static str,
    pub bellatrix_execution_payload_header_json: &'static str,
    pub capella_execution_payload_json: &'static str,
    pub capella_execution_payload_header_json: &'static str,
    pub deneb_execution_payload_json: &'static str,
    pub deneb_execution_payload_header_json: &'static str,
    pub v1_validator_registration_json: &'static str,
    pub v1_beacon_committee_selection_json: &'static str,
    pub v1_sync_committee_selection_json: &'static str,
    pub deneb_kzg_commitment_json: &'static str,
    pub electra_oversized_attestation_json: &'static str,
}

pub(crate) const VECTORS: Vectors = Vectors {
    phase0_deposit_root: PHASE0_DEPOSIT_ROOT,
    bellatrix_execution_payload_root: BELLATRIX_EXECUTION_PAYLOAD_ROOT,
    bellatrix_execution_payload_header_root: BELLATRIX_EXECUTION_PAYLOAD_HEADER_ROOT,
    capella_execution_payload_root: CAPELLA_EXECUTION_PAYLOAD_ROOT,
    capella_execution_payload_header_root: CAPELLA_EXECUTION_PAYLOAD_HEADER_ROOT,
    deneb_execution_payload_root: DENEB_EXECUTION_PAYLOAD_ROOT,
    deneb_execution_payload_header_root: DENEB_EXECUTION_PAYLOAD_HEADER_ROOT,
    phase0_beacon_block_body_root: PHASE0_BEACON_BLOCK_BODY_ROOT,
    phase0_beacon_block_root: PHASE0_BEACON_BLOCK_ROOT,
    altair_beacon_block_body_root: ALTAIR_BEACON_BLOCK_BODY_ROOT,
    altair_beacon_block_root: ALTAIR_BEACON_BLOCK_ROOT,
    bellatrix_beacon_block_body_root: BELLATRIX_BEACON_BLOCK_BODY_ROOT,
    bellatrix_beacon_block_root: BELLATRIX_BEACON_BLOCK_ROOT,
    capella_beacon_block_body_root: CAPELLA_BEACON_BLOCK_BODY_ROOT,
    capella_beacon_block_root: CAPELLA_BEACON_BLOCK_ROOT,
    deneb_beacon_block_body_root: DENEB_BEACON_BLOCK_BODY_ROOT,
    deneb_beacon_block_root: DENEB_BEACON_BLOCK_ROOT,
    electra_beacon_block_body_root: ELECTRA_BEACON_BLOCK_BODY_ROOT,
    electra_beacon_block_root: ELECTRA_BEACON_BLOCK_ROOT,
    fulu_beacon_block_body_root: FULU_BEACON_BLOCK_BODY_ROOT,
    fulu_beacon_block_root: FULU_BEACON_BLOCK_ROOT,
    bellatrix_execution_payload_json: BELLATRIX_EXECUTION_PAYLOAD_JSON,
    bellatrix_execution_payload_header_json: BELLATRIX_EXECUTION_PAYLOAD_HEADER_JSON,
    capella_execution_payload_json: CAPELLA_EXECUTION_PAYLOAD_JSON,
    capella_execution_payload_header_json: CAPELLA_EXECUTION_PAYLOAD_HEADER_JSON,
    deneb_execution_payload_json: DENEB_EXECUTION_PAYLOAD_JSON,
    deneb_execution_payload_header_json: DENEB_EXECUTION_PAYLOAD_HEADER_JSON,
    v1_validator_registration_json: V1_VALIDATOR_REGISTRATION_JSON,
    v1_beacon_committee_selection_json: V1_BEACON_COMMITTEE_SELECTION_JSON,
    v1_sync_committee_selection_json: V1_SYNC_COMMITTEE_SELECTION_JSON,
    deneb_kzg_commitment_json: DENEB_KZG_COMMITMENT_JSON,
    electra_oversized_attestation_json: ELECTRA_OVERSIZED_ATTESTATION_JSON,
};

pub(crate) fn seq<const N: usize>(start: u8) -> [u8; N] {
    let mut out = [0_u8; N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = start.wrapping_add(u8::try_from(i).expect("i fits in u8"));
    }
    out
}

pub(crate) fn u256_from_u64(value: u64) -> deneb::BaseFeePerGas {
    deneb::BaseFeePerGas::from(value)
}

pub(crate) fn tree_hash_hex<T: TreeHash>(value: &T) -> String {
    hex::encode(value.tree_hash_root().0)
}

pub(crate) fn parse_json_value(json: &str) -> Value {
    serde_json::from_str(json).expect("valid json")
}

pub(crate) fn to_json_value<T: serde::Serialize>(value: &T) -> Value {
    serde_json::to_value(value).expect("serde_json::to_value should succeed")
}

pub(crate) fn assert_json_eq(actual: Value, expected_json: &str) {
    assert_eq!(actual, parse_json_value(expected_json));
}

fn attestation_data_fixture() -> phase0::AttestationData {
    phase0::AttestationData {
        slot: 11,
        index: 7,
        beacon_block_root: seq::<32>(0xA0),
        source: phase0::Checkpoint {
            epoch: 3,
            root: seq::<32>(0xB0),
        },
        target: phase0::Checkpoint {
            epoch: 4,
            root: seq::<32>(0xC0),
        },
    }
}

pub(crate) fn phase0_deposit_fixture() -> phase0::Deposit {
    phase0::Deposit {
        proof: phase0::SszVector((1_u8..=33).map(seq::<32>).collect()),
        data: phase0::DepositData {
            pubkey: seq::<48>(0x10),
            withdrawal_credentials: seq::<32>(0x20),
            amount: 32_000_000_000,
            signature: seq::<96>(0x30),
        },
    }
}

pub(crate) fn phase0_beacon_block_body_fixture() -> phase0::BeaconBlockBody {
    let eth1_data = phase0::ETH1Data {
        deposit_root: seq::<32>(0xD0),
        deposit_count: 123,
        block_hash: seq::<32>(0xD1),
    };

    let proposer_slashing = phase0::ProposerSlashing {
        signed_header_1: phase0::SignedBeaconBlockHeader {
            message: phase0::BeaconBlockHeader {
                slot: 1,
                proposer_index: 2,
                parent_root: seq::<32>(0xA0),
                state_root: seq::<32>(0xA1),
                body_root: seq::<32>(0xA2),
            },
            signature: seq::<96>(0xA3),
        },
        signed_header_2: phase0::SignedBeaconBlockHeader {
            message: phase0::BeaconBlockHeader {
                slot: 1,
                proposer_index: 2,
                parent_root: seq::<32>(0xB0),
                state_root: seq::<32>(0xB1),
                body_root: seq::<32>(0xB2),
            },
            signature: seq::<96>(0xB3),
        },
    };

    let indexed_attestation_1 = phase0::IndexedAttestation {
        attesting_indices: phase0::SszList(vec![11, 12]),
        data: attestation_data_fixture(),
        signature: seq::<96>(0xC0),
    };
    let indexed_attestation_2 = phase0::IndexedAttestation {
        attesting_indices: phase0::SszList(vec![13, 14]),
        data: attestation_data_fixture(),
        signature: seq::<96>(0xC1),
    };
    let attester_slashing = phase0::AttesterSlashing {
        attestation_1: indexed_attestation_1,
        attestation_2: indexed_attestation_2,
    };

    let aggregation_bits = BitList::<2048>::with_bits(8, &[0]);
    let attestation = phase0::Attestation {
        aggregation_bits,
        data: attestation_data_fixture(),
        signature: seq::<96>(0xC2),
    };

    let voluntary_exit = phase0::SignedVoluntaryExit {
        message: phase0::VoluntaryExit {
            epoch: 3,
            validator_index: 4,
        },
        signature: seq::<96>(0xC3),
    };

    phase0::BeaconBlockBody {
        randao_reveal: seq::<96>(0x90),
        eth1_data,
        graffiti: seq::<32>(0x91),
        proposer_slashings: phase0::SszList(vec![proposer_slashing]),
        attester_slashings: phase0::SszList(vec![attester_slashing]),
        attestations: phase0::SszList(vec![attestation]),
        deposits: phase0::SszList(vec![phase0_deposit_fixture()]),
        voluntary_exits: phase0::SszList(vec![voluntary_exit]),
    }
}

pub(crate) fn phase0_beacon_block_fixture() -> phase0::BeaconBlock {
    phase0::BeaconBlock {
        slot: 123,
        proposer_index: 7,
        parent_root: seq::<32>(0x92),
        state_root: seq::<32>(0x93),
        body: phase0_beacon_block_body_fixture(),
    }
}

fn altair_sync_aggregate_fixture() -> altair::SyncAggregate {
    altair::SyncAggregate {
        sync_committee_bits: BitVector::<512>::with_bits(&[0]),
        sync_committee_signature: seq::<96>(0x94),
    }
}

pub(crate) fn altair_beacon_block_body_fixture() -> altair::BeaconBlockBody {
    let phase0_body = phase0_beacon_block_body_fixture();
    altair::BeaconBlockBody {
        randao_reveal: phase0_body.randao_reveal,
        eth1_data: phase0_body.eth1_data,
        graffiti: phase0_body.graffiti,
        proposer_slashings: phase0_body.proposer_slashings,
        attester_slashings: phase0_body.attester_slashings,
        attestations: phase0_body.attestations,
        deposits: phase0_body.deposits,
        voluntary_exits: phase0_body.voluntary_exits,
        sync_aggregate: altair_sync_aggregate_fixture(),
    }
}

pub(crate) fn altair_beacon_block_fixture() -> altair::BeaconBlock {
    let phase0_block = phase0_beacon_block_fixture();
    altair::BeaconBlock {
        slot: phase0_block.slot,
        proposer_index: phase0_block.proposer_index,
        parent_root: phase0_block.parent_root,
        state_root: phase0_block.state_root,
        body: altair_beacon_block_body_fixture(),
    }
}

pub(crate) fn bellatrix_execution_payload_fixture() -> bellatrix::ExecutionPayload {
    bellatrix::ExecutionPayload {
        parent_hash: seq::<32>(0x01),
        fee_recipient: seq::<20>(0x11),
        state_root: seq::<32>(0x21),
        receipts_root: seq::<32>(0x31),
        logs_bloom: seq::<256>(0x41),
        prev_randao: seq::<32>(0x51),
        block_number: 12_345,
        gas_limit: 30_000_000,
        gas_used: 12_345_678,
        timestamp: 1_700_000_000,
        extra_data: phase0::SszList(vec![0xAA, 0xBB, 0xCC]),
        base_fee_per_gas: bellatrix::BaseFeePerGas::from(123_456_789_u64),
        block_hash: seq::<32>(0x61),
        transactions: phase0::SszList(vec![
            bellatrix::Transaction::from(vec![0xDE, 0xAD]),
            bellatrix::Transaction::from(vec![0xBE, 0xEF, 0x01]),
        ]),
    }
}

pub(crate) fn bellatrix_execution_payload_header_fixture() -> bellatrix::ExecutionPayloadHeader {
    let payload = bellatrix_execution_payload_fixture();
    bellatrix::ExecutionPayloadHeader {
        parent_hash: payload.parent_hash,
        fee_recipient: payload.fee_recipient,
        state_root: payload.state_root,
        receipts_root: payload.receipts_root,
        logs_bloom: payload.logs_bloom,
        prev_randao: payload.prev_randao,
        block_number: payload.block_number,
        gas_limit: payload.gas_limit,
        gas_used: payload.gas_used,
        timestamp: payload.timestamp,
        extra_data: payload.extra_data,
        base_fee_per_gas: payload.base_fee_per_gas,
        block_hash: payload.block_hash,
        transactions_root: seq::<32>(0x71),
    }
}

pub(crate) fn bellatrix_beacon_block_body_fixture() -> bellatrix::BeaconBlockBody {
    let phase0_body = phase0_beacon_block_body_fixture();
    bellatrix::BeaconBlockBody {
        randao_reveal: phase0_body.randao_reveal,
        eth1_data: phase0_body.eth1_data,
        graffiti: phase0_body.graffiti,
        proposer_slashings: phase0_body.proposer_slashings,
        attester_slashings: phase0_body.attester_slashings,
        attestations: phase0_body.attestations,
        deposits: phase0_body.deposits,
        voluntary_exits: phase0_body.voluntary_exits,
        sync_aggregate: altair_sync_aggregate_fixture(),
        execution_payload: bellatrix_execution_payload_fixture(),
    }
}

pub(crate) fn bellatrix_beacon_block_fixture() -> bellatrix::BeaconBlock {
    let phase0_block = phase0_beacon_block_fixture();
    bellatrix::BeaconBlock {
        slot: phase0_block.slot,
        proposer_index: phase0_block.proposer_index,
        parent_root: phase0_block.parent_root,
        state_root: phase0_block.state_root,
        body: bellatrix_beacon_block_body_fixture(),
    }
}

pub(crate) fn capella_execution_payload_fixture() -> capella::ExecutionPayload {
    capella::ExecutionPayload {
        parent_hash: seq::<32>(0x01),
        fee_recipient: seq::<20>(0x11),
        state_root: seq::<32>(0x21),
        receipts_root: seq::<32>(0x31),
        logs_bloom: seq::<256>(0x41),
        prev_randao: seq::<32>(0x51),
        block_number: 22_222,
        gas_limit: 31_000_000,
        gas_used: 10_000_000,
        timestamp: 1_700_000_123,
        extra_data: phase0::SszList(vec![0x01, 0x02, 0x03, 0x04]),
        base_fee_per_gas: bellatrix::BaseFeePerGas::from(987_654_321_u64),
        block_hash: seq::<32>(0x81),
        transactions: phase0::SszList(vec![bellatrix::Transaction::from(vec![0xAB, 0xCD, 0xEF])]),
        withdrawals: phase0::SszList(vec![capella::Withdrawal {
            index: 1,
            validator_index: 2,
            address: seq::<20>(0x91),
            amount: 3_333_333_333,
        }]),
    }
}

pub(crate) fn capella_execution_payload_header_fixture() -> capella::ExecutionPayloadHeader {
    let payload = capella_execution_payload_fixture();
    capella::ExecutionPayloadHeader {
        parent_hash: payload.parent_hash,
        fee_recipient: payload.fee_recipient,
        state_root: payload.state_root,
        receipts_root: payload.receipts_root,
        logs_bloom: payload.logs_bloom,
        prev_randao: payload.prev_randao,
        block_number: payload.block_number,
        gas_limit: payload.gas_limit,
        gas_used: payload.gas_used,
        timestamp: payload.timestamp,
        extra_data: payload.extra_data,
        base_fee_per_gas: payload.base_fee_per_gas,
        block_hash: payload.block_hash,
        transactions_root: seq::<32>(0xA1),
        withdrawals_root: seq::<32>(0xA2),
    }
}

fn capella_signed_bls_to_execution_change_fixture() -> capella::SignedBLSToExecutionChange {
    capella::SignedBLSToExecutionChange {
        message: capella::BLSToExecutionChange {
            validator_index: 99,
            from_bls_pubkey: seq::<48>(0x95),
            to_execution_address: seq::<20>(0x96),
        },
        signature: seq::<96>(0x97),
    }
}

pub(crate) fn capella_beacon_block_body_fixture() -> capella::BeaconBlockBody {
    let phase0_body = phase0_beacon_block_body_fixture();
    capella::BeaconBlockBody {
        randao_reveal: phase0_body.randao_reveal,
        eth1_data: phase0_body.eth1_data,
        graffiti: phase0_body.graffiti,
        proposer_slashings: phase0_body.proposer_slashings,
        attester_slashings: phase0_body.attester_slashings,
        attestations: phase0_body.attestations,
        deposits: phase0_body.deposits,
        voluntary_exits: phase0_body.voluntary_exits,
        sync_aggregate: altair_sync_aggregate_fixture(),
        execution_payload: capella_execution_payload_fixture(),
        bls_to_execution_changes: phase0::SszList(vec![
            capella_signed_bls_to_execution_change_fixture(),
        ]),
    }
}

pub(crate) fn capella_beacon_block_fixture() -> capella::BeaconBlock {
    let phase0_block = phase0_beacon_block_fixture();
    capella::BeaconBlock {
        slot: phase0_block.slot,
        proposer_index: phase0_block.proposer_index,
        parent_root: phase0_block.parent_root,
        state_root: phase0_block.state_root,
        body: capella_beacon_block_body_fixture(),
    }
}

pub(crate) fn deneb_execution_payload_fixture() -> deneb::ExecutionPayload {
    deneb::ExecutionPayload {
        parent_hash: seq::<32>(0x01),
        fee_recipient: seq::<20>(0x11),
        state_root: seq::<32>(0x21),
        receipts_root: seq::<32>(0x31),
        logs_bloom: seq::<256>(0x41),
        prev_randao: seq::<32>(0x51),
        block_number: 33_333,
        gas_limit: 32_000_000,
        gas_used: 8_888_888,
        timestamp: 1_700_000_456,
        extra_data: phase0::SszList(vec![0x0A, 0x0B]),
        base_fee_per_gas: u256_from_u64(42),
        block_hash: seq::<32>(0xB1),
        transactions: phase0::SszList(vec![
            bellatrix::Transaction::from(vec![0x01]),
            bellatrix::Transaction::from(vec![0x02, 0x03]),
        ]),
        withdrawals: phase0::SszList(vec![capella::Withdrawal {
            index: 9,
            validator_index: 10,
            address: seq::<20>(0xB2),
            amount: 4_444,
        }]),
        blob_gas_used: 777,
        excess_blob_gas: 888,
    }
}

pub(crate) fn deneb_execution_payload_header_fixture() -> deneb::ExecutionPayloadHeader {
    let payload = deneb_execution_payload_fixture();
    deneb::ExecutionPayloadHeader {
        parent_hash: payload.parent_hash,
        fee_recipient: payload.fee_recipient,
        state_root: payload.state_root,
        receipts_root: payload.receipts_root,
        logs_bloom: payload.logs_bloom,
        prev_randao: payload.prev_randao,
        block_number: payload.block_number,
        gas_limit: payload.gas_limit,
        gas_used: payload.gas_used,
        timestamp: payload.timestamp,
        extra_data: payload.extra_data,
        base_fee_per_gas: payload.base_fee_per_gas,
        block_hash: payload.block_hash,
        transactions_root: seq::<32>(0xC1),
        withdrawals_root: seq::<32>(0xC2),
        blob_gas_used: payload.blob_gas_used,
        excess_blob_gas: payload.excess_blob_gas,
    }
}

pub(crate) fn deneb_kzg_commitment_fixture() -> deneb::KZGCommitment {
    deneb::KZGCommitment {
        bytes: seq::<48>(0xE1),
    }
}

pub(crate) fn deneb_beacon_block_body_fixture() -> deneb::BeaconBlockBody {
    let phase0_body = phase0_beacon_block_body_fixture();
    deneb::BeaconBlockBody {
        randao_reveal: phase0_body.randao_reveal,
        eth1_data: phase0_body.eth1_data,
        graffiti: phase0_body.graffiti,
        proposer_slashings: phase0_body.proposer_slashings,
        attester_slashings: phase0_body.attester_slashings,
        attestations: phase0_body.attestations,
        deposits: phase0_body.deposits,
        voluntary_exits: phase0_body.voluntary_exits,
        sync_aggregate: altair_sync_aggregate_fixture(),
        execution_payload: deneb_execution_payload_fixture(),
        bls_to_execution_changes: phase0::SszList(vec![
            capella_signed_bls_to_execution_change_fixture(),
        ]),
        blob_kzg_commitments: phase0::SszList(vec![deneb_kzg_commitment_fixture()]),
    }
}

pub(crate) fn deneb_beacon_block_fixture() -> deneb::BeaconBlock {
    let phase0_block = phase0_beacon_block_fixture();
    deneb::BeaconBlock {
        slot: phase0_block.slot,
        proposer_index: phase0_block.proposer_index,
        parent_root: phase0_block.parent_root,
        state_root: phase0_block.state_root,
        body: deneb_beacon_block_body_fixture(),
    }
}

fn electra_attestation_fixture() -> electra::Attestation {
    electra::Attestation {
        aggregation_bits: BitList::<131_072>::with_bits(8, &[0]),
        data: attestation_data_fixture(),
        signature: seq::<96>(0x98),
        committee_bits: BitVector::<64>::with_bits(&[1]),
    }
}

fn electra_attester_slashing_fixture() -> electra::AttesterSlashing {
    let indexed_1 = electra::IndexedAttestation {
        attesting_indices: phase0::SszList(vec![21, 22]),
        data: attestation_data_fixture(),
        signature: seq::<96>(0x99),
    };
    let indexed_2 = electra::IndexedAttestation {
        attesting_indices: phase0::SszList(vec![23, 24]),
        data: attestation_data_fixture(),
        signature: seq::<96>(0x9A),
    };
    electra::AttesterSlashing {
        attestation_1: indexed_1,
        attestation_2: indexed_2,
    }
}

fn electra_execution_requests_fixture() -> electra::ExecutionRequests {
    electra::ExecutionRequests {
        deposits: phase0::SszList(vec![electra::DepositRequest {
            pubkey: seq::<48>(0x9B),
            withdrawal_credentials: seq::<32>(0x9C),
            amount: 1234,
            signature: seq::<96>(0x9D),
            index: 5,
        }]),
        withdrawals: phase0::SszList(vec![electra::WithdrawalRequest {
            source_address: seq::<20>(0x9E),
            validator_pubkey: seq::<48>(0x9F),
            amount: 4321,
        }]),
        consolidations: phase0::SszList(vec![electra::ConsolidationRequest {
            source_address: seq::<20>(0xA4),
            source_pubkey: seq::<48>(0xA5),
            target_pubkey: seq::<48>(0xA6),
        }]),
    }
}

pub(crate) fn electra_beacon_block_body_fixture() -> electra::BeaconBlockBody {
    let phase0_body = phase0_beacon_block_body_fixture();
    electra::BeaconBlockBody {
        randao_reveal: phase0_body.randao_reveal,
        eth1_data: phase0_body.eth1_data,
        graffiti: phase0_body.graffiti,
        proposer_slashings: phase0_body.proposer_slashings,
        attester_slashings: phase0::SszList(vec![electra_attester_slashing_fixture()]),
        attestations: phase0::SszList(vec![electra_attestation_fixture()]),
        deposits: phase0_body.deposits,
        voluntary_exits: phase0_body.voluntary_exits,
        sync_aggregate: altair_sync_aggregate_fixture(),
        execution_payload: deneb_execution_payload_fixture(),
        bls_to_execution_changes: phase0::SszList(vec![
            capella_signed_bls_to_execution_change_fixture(),
        ]),
        blob_kzg_commitments: phase0::SszList(vec![deneb_kzg_commitment_fixture()]),
        execution_requests: electra_execution_requests_fixture(),
    }
}

pub(crate) fn electra_beacon_block_fixture() -> electra::BeaconBlock {
    let phase0_block = phase0_beacon_block_fixture();
    electra::BeaconBlock {
        slot: phase0_block.slot,
        proposer_index: phase0_block.proposer_index,
        parent_root: phase0_block.parent_root,
        state_root: phase0_block.state_root,
        body: electra_beacon_block_body_fixture(),
    }
}

pub(crate) fn fulu_beacon_block_body_fixture() -> electra::BeaconBlockBody {
    electra_beacon_block_body_fixture()
}

pub(crate) fn fulu_beacon_block_fixture() -> electra::BeaconBlock {
    electra_beacon_block_fixture()
}
