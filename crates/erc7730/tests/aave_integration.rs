//! Integration tests using real Aave v2/v3 registry descriptors.

use erc7730::decoder::parse_signature;
use erc7730::token::{CompositeTokenSource, StaticTokenSource, TokenMeta, WellKnownTokenSource};
use erc7730::types::descriptor::Descriptor;
use erc7730::{format_calldata_with_from, DisplayEntry, DisplayModel};

fn load_descriptor(fixture: &str) -> Descriptor {
    let path = format!("{}/tests/fixtures/{fixture}", env!("CARGO_MANIFEST_DIR"));
    let json = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    Descriptor::from_json(&json).unwrap_or_else(|e| panic!("parse {path}: {e}"))
}

fn build_calldata(selector: &[u8; 4], args: &[Vec<u8>]) -> Vec<u8> {
    let mut data = Vec::with_capacity(4 + args.len() * 32);
    data.extend_from_slice(selector);
    for arg in args {
        data.extend_from_slice(arg);
    }
    data
}

fn address_word(hex_addr: &str) -> Vec<u8> {
    let hex_str = hex_addr
        .strip_prefix("0x")
        .or_else(|| hex_addr.strip_prefix("0X"))
        .unwrap_or(hex_addr);
    let addr_bytes = hex::decode(hex_str).expect("valid hex address");
    let mut word = vec![0u8; 12];
    word.extend_from_slice(&addr_bytes);
    assert_eq!(word.len(), 32);
    word
}

fn uint_word(val: u128) -> Vec<u8> {
    let mut word = vec![0u8; 16];
    word.extend_from_slice(&val.to_be_bytes());
    assert_eq!(word.len(), 32);
    word
}

fn max_uint256_word() -> Vec<u8> {
    vec![0xff; 32]
}

fn aave_token_source() -> CompositeTokenSource {
    let mut custom = StaticTokenSource::new();
    // Aave uses these token addresses in tests
    custom.insert(
        1,
        "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
        TokenMeta {
            symbol: "USDC".to_string(),
            decimals: 6,
            name: "USD Coin".to_string(),
        },
    );
    custom.insert(
        1,
        "0x6b175474e89094c44da98b954eedeac495271d0f",
        TokenMeta {
            symbol: "DAI".to_string(),
            decimals: 18,
            name: "Dai Stablecoin".to_string(),
        },
    );
    custom.insert(
        1,
        "0xdac17f958d2ee523a2206206994597c13d831ec7",
        TokenMeta {
            symbol: "USDT".to_string(),
            decimals: 6,
            name: "Tether USD".to_string(),
        },
    );
    custom.insert(
        8453,
        "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
        TokenMeta {
            symbol: "USDC".to_string(),
            decimals: 6,
            name: "USD Coin".to_string(),
        },
    );
    CompositeTokenSource::new(vec![
        Box::new(custom),
        Box::new(WellKnownTokenSource::new()),
    ])
}

fn get_entry_value(model: &DisplayModel, label: &str) -> String {
    for entry in &model.entries {
        match entry {
            DisplayEntry::Item(item) if item.label == label => return item.value.clone(),
            _ => {}
        }
    }
    panic!("no entry with label '{label}' found in {:?}", model.entries);
}

// --- LPv3 Tests ---

#[test]
fn aave_supply_usdc_mainnet() {
    let descriptor = load_descriptor("aave-lpv3.json");
    let sig = parse_signature("supply(address,uint256,address,uint16)").unwrap();
    let tokens = aave_token_source();

    let usdc_addr = "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";
    let on_behalf = "1111111111111111111111111111111111111111";

    let calldata = build_calldata(
        &sig.selector,
        &[
            address_word(usdc_addr),
            uint_word(1_000_000_000), // 1000 USDC (6 decimals)
            address_word(on_behalf),
            uint_word(0), // referralCode
        ],
    );

    let result = format_calldata_with_from(
        &descriptor,
        1,
        "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2",
        &calldata,
        None,
        None,
        &tokens,
    )
    .unwrap();

    assert_eq!(result.intent, "Supply");
    assert_eq!(get_entry_value(&result, "Amount to supply"), "1000 USDC");
}

#[test]
fn aave_supply_usdc_base() {
    let descriptor = load_descriptor("aave-lpv3.json");
    let sig = parse_signature("supply(address,uint256,address,uint16)").unwrap();
    let tokens = aave_token_source();

    let usdc_base = "833589fcd6edb6e08f4c7c32d4f71b54bda02913";
    let on_behalf = "2222222222222222222222222222222222222222";

    let calldata = build_calldata(
        &sig.selector,
        &[
            address_word(usdc_base),
            uint_word(500_000_000), // 500 USDC
            address_word(on_behalf),
            uint_word(0),
        ],
    );

    let result = format_calldata_with_from(
        &descriptor,
        8453,
        "0xA238Dd80C259a72e81d7e4664a9801593F98d1c5",
        &calldata,
        None,
        None,
        &tokens,
    )
    .unwrap();

    assert_eq!(result.intent, "Supply");
    assert_eq!(get_entry_value(&result, "Amount to supply"), "500 USDC");
}

#[test]
fn aave_repay_all_dai() {
    let descriptor = load_descriptor("aave-lpv3.json");
    let sig = parse_signature("repay(address,uint256,uint256,address)").unwrap();
    let tokens = aave_token_source();

    let dai_addr = "6b175474e89094c44da98b954eedeac495271d0f";
    let on_behalf = "3333333333333333333333333333333333333333";

    let calldata = build_calldata(
        &sig.selector,
        &[
            address_word(dai_addr),
            max_uint256_word(), // max uint256 = "All"
            uint_word(2),       // variable rate
            address_word(on_behalf),
        ],
    );

    let result = format_calldata_with_from(
        &descriptor,
        1,
        "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2",
        &calldata,
        None,
        None,
        &tokens,
    )
    .unwrap();

    assert_eq!(result.intent, "Repay loan");
    assert_eq!(get_entry_value(&result, "Amount to repay"), "All DAI");
    assert_eq!(get_entry_value(&result, "Interest rate mode"), "variable");
}

#[test]
fn aave_withdraw_max() {
    let descriptor = load_descriptor("aave-lpv3.json");
    let sig = parse_signature("withdraw(address,uint256,address)").unwrap();
    let tokens = aave_token_source();

    let usdc_addr = "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";
    let to_addr = "4444444444444444444444444444444444444444";

    let calldata = build_calldata(
        &sig.selector,
        &[
            address_word(usdc_addr),
            max_uint256_word(), // max = "Max"
            address_word(to_addr),
        ],
    );

    let result = format_calldata_with_from(
        &descriptor,
        1,
        "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2",
        &calldata,
        None,
        None,
        &tokens,
    )
    .unwrap();

    assert_eq!(result.intent, "Withdraw");
    assert_eq!(get_entry_value(&result, "Amount to withdraw"), "Max USDC");
}

#[test]
fn aave_borrow_variable() {
    let descriptor = load_descriptor("aave-lpv3.json");
    let sig = parse_signature("borrow(address,uint256,uint256,uint16,address)").unwrap();
    let tokens = aave_token_source();

    let usdt_addr = "dac17f958d2ee523a2206206994597c13d831ec7";
    let on_behalf = "5555555555555555555555555555555555555555";

    let calldata = build_calldata(
        &sig.selector,
        &[
            address_word(usdt_addr),
            uint_word(5_000_000), // 5 USDT
            uint_word(2),         // variable rate
            uint_word(0),         // referralCode
            address_word(on_behalf),
        ],
    );

    let result = format_calldata_with_from(
        &descriptor,
        1,
        "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2",
        &calldata,
        None,
        None,
        &tokens,
    )
    .unwrap();

    assert_eq!(result.intent, "Borrow");
    assert_eq!(get_entry_value(&result, "Amount to borrow"), "5 USDT");
    assert_eq!(get_entry_value(&result, "Interest Rate mode"), "variable");
}

#[test]
fn aave_set_collateral() {
    let descriptor = load_descriptor("aave-lpv3.json");
    let sig = parse_signature("setUserUseReserveAsCollateral(address,bool)").unwrap();
    let tokens = aave_token_source();

    let usdc_addr = "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";

    let calldata = build_calldata(
        &sig.selector,
        &[
            address_word(usdc_addr),
            uint_word(1), // true
        ],
    );

    let result = format_calldata_with_from(
        &descriptor,
        1,
        "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2",
        &calldata,
        None,
        None,
        &tokens,
    )
    .unwrap();

    assert_eq!(result.intent, "Manage collateral");
    assert_eq!(get_entry_value(&result, "Enable use as collateral"), "true");
}

// --- LPv2 Tests ---

#[test]
fn aave_deposit_usdc_mainnet() {
    let descriptor = load_descriptor("aave-lpv2.json");
    let sig = parse_signature("deposit(address,uint256,address,uint16)").unwrap();
    let tokens = aave_token_source();

    let usdc_addr = "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";
    let on_behalf = "1111111111111111111111111111111111111111";

    let calldata = build_calldata(
        &sig.selector,
        &[
            address_word(usdc_addr),
            uint_word(1_000_000_000), // 1000 USDC
            address_word(on_behalf),
            uint_word(0),
        ],
    );

    let result = format_calldata_with_from(
        &descriptor,
        1,
        "0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9",
        &calldata,
        None,
        None,
        &tokens,
    )
    .unwrap();

    assert_eq!(result.intent, "Supply");
    assert_eq!(get_entry_value(&result, "Amount to supply"), "1000 USDC");
}

// --- WrappedTokenGatewayV3 Tests ---

#[test]
fn gateway_deposit_eth() {
    let descriptor = load_descriptor("aave-gateway.json");
    let sig = parse_signature("depositETH(address,address,uint16)").unwrap();
    let tokens = aave_token_source();

    let pool_addr = "87870bca3f3fd6335c3f4ce8392d69350b4fa4e2";
    let on_behalf = "6666666666666666666666666666666666666666";

    let calldata = build_calldata(
        &sig.selector,
        &[
            address_word(pool_addr),
            address_word(on_behalf),
            uint_word(0),
        ],
    );

    // 1 ETH = 10^18 wei
    let value = uint_word(1_000_000_000_000_000_000);

    let result = format_calldata_with_from(
        &descriptor,
        1,
        "0xd01607c3C5eCABa394D8be377a08590149325722",
        &calldata,
        Some(&value),
        None,
        &tokens,
    )
    .unwrap();

    assert_eq!(result.intent, "Supply");
    // @.value should be formatted as native currency (ETH with 18 decimals)
    let amount = get_entry_value(&result, "Amount to supply");
    assert_eq!(amount, "1 ETH");
}

#[test]
fn gateway_borrow_eth_with_from() {
    let descriptor = load_descriptor("aave-gateway.json");
    let sig = parse_signature("borrowETH(address,uint256,uint16)").unwrap();
    let tokens = aave_token_source();

    let pool_addr = "87870bca3f3fd6335c3f4ce8392d69350b4fa4e2";

    let calldata = build_calldata(
        &sig.selector,
        &[
            address_word(pool_addr),
            uint_word(500_000_000_000_000_000), // 0.5 ETH
            uint_word(0),
        ],
    );

    let from_addr = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    let result = format_calldata_with_from(
        &descriptor,
        1,
        "0xd01607c3C5eCABa394D8be377a08590149325722",
        &calldata,
        None,
        Some(from_addr),
        &tokens,
    )
    .unwrap();

    assert_eq!(result.intent, "Borrow");
    // @.from should be resolved (EIP-55 checksummed)
    let debtor = get_entry_value(&result, "Debtor");
    assert!(
        debtor.to_lowercase().contains("aaaaaa"),
        "debtor should contain the from address: {debtor}"
    );
}

/// Real wallet request: depositETH with value=0x5af3107a4000 (0.0001 ETH) on mainnet.
/// Verifies @.value with format "amount" renders native currency (decimals + symbol).
#[test]
fn real_wallet_supply_eth_mainnet() {
    let descriptor = load_descriptor("aave-gateway.json");
    let tokens = aave_token_source();

    // depositETH(address,address,uint16) calldata from real wallet
    let calldata = hex::decode(
        "474cf53d\
         00000000000000000000000087870bca3f3fd6335c3f4ce8392d69350b4fa4e2\
         000000000000000000000000bf01daf454dce008d3e2bfd47d5e186f71477253\
         0000000000000000000000000000000000000000000000000000000000000000",
    )
    .unwrap();

    // value = 0x5af3107a4000 = 100000000000000 wei = 0.0001 ETH
    let value_bytes =
        hex::decode("00000000000000000000000000000000000000000000000000005af3107a4000").unwrap();

    let result = format_calldata_with_from(
        &descriptor,
        1,
        "0xd01607c3C5eCABa394D8be377a08590149325722",
        &calldata,
        Some(&value_bytes),
        Some("0xbf01daf454dce008d3e2bfd47d5e186f71477253"),
        &tokens,
    )
    .unwrap();

    assert_eq!(result.intent, "Supply");
    assert_eq!(get_entry_value(&result, "Amount to supply"), "0.0001 ETH");

    // Interpolated intent should show "0.0001 ETH", not raw wei
    let interp = result.interpolated_intent.as_deref().unwrap();
    assert!(
        interp.contains("0.0001 ETH"),
        "interpolated intent should contain '0.0001 ETH': {interp}"
    );
    assert!(
        !interp.contains("100000000000000"),
        "interpolated intent should NOT contain raw wei: {interp}"
    );
}

#[test]
fn aave_interpolated_intent() {
    let descriptor = load_descriptor("aave-lpv3.json");
    let sig = parse_signature("supply(address,uint256,address,uint16)").unwrap();
    let tokens = aave_token_source();

    let usdc_addr = "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";
    let on_behalf = "1111111111111111111111111111111111111111";

    let calldata = build_calldata(
        &sig.selector,
        &[
            address_word(usdc_addr),
            uint_word(1_000_000_000), // 1000 USDC
            address_word(on_behalf),
            uint_word(0),
        ],
    );

    let result = format_calldata_with_from(
        &descriptor,
        1,
        "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2",
        &calldata,
        None,
        None,
        &tokens,
    )
    .unwrap();

    // interpolatedIntent: "Supply {amount} for {onBehalfOf}"
    let intent = result.interpolated_intent.as_deref().unwrap();
    assert!(
        intent.contains("1000 USDC"),
        "interpolated intent should contain formatted amount: {intent}"
    );
    assert!(
        intent.contains("1111111111"),
        "interpolated intent should contain the address: {intent}"
    );
}

// --- Graceful Degradation Test ---

#[test]
fn graceful_fallback_unknown_selector() {
    let descriptor = load_descriptor("aave-lpv3.json");
    let tokens = aave_token_source();

    // Unknown function selector
    let calldata = hex::decode(
        "deadbeef000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000003e8",
    )
    .unwrap();

    let result = format_calldata_with_from(
        &descriptor,
        1,
        "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2",
        &calldata,
        None,
        None,
        &tokens,
    )
    .unwrap();

    assert!(result.intent.contains("0xdeadbeef"));
    assert!(!result.warnings.is_empty());
    assert!(result.warnings[0].contains("No matching descriptor format found"));
}

// --- L2 encoded withdraw(bytes32) on Optimism ---
// Real wallet data: Aave V3 Pool on Optimism uses L2-encoded functions
// where params are packed into a single bytes32 instead of separate args.
// The descriptor only has withdraw(address,uint256,address) (selector 0x69328dec),
// so the L2 variant withdraw(bytes32) (selector 0x8e19899e) falls back to raw preview.
#[test]
fn aave_withdraw_bytes32_optimism_graceful_fallback() {
    let descriptor = load_descriptor("aave-lpv3.json");
    let tokens = aave_token_source();

    // Exact calldata from wallet: withdraw(bytes32) on Optimism chain 10
    let calldata =
        hex::decode("8e19899e0000000000000000000000000000ffffffffffffffffffffffffffffffff0005")
            .unwrap();

    let result = format_calldata_with_from(
        &descriptor,
        10,
        "0x794a61358d6845594f94dc1db02a252b5b4814ad",
        &calldata,
        Some(&[0x00]),
        Some("0xbf01daf454dce008d3e2bfd47d5e186f71477253"),
        &tokens,
    )
    .unwrap();

    // No format key matches selector 0x8e19899e, so we get graceful fallback
    assert!(
        result.intent.contains("0x8e19899e"),
        "should fall back to unknown function: {}",
        result.intent
    );
    assert!(!result.warnings.is_empty());
    assert!(result.warnings[0].contains("No matching descriptor format found"));
    // The single bytes32 arg should appear as a raw param
    assert_eq!(result.entries.len(), 1);
}

// --- Real Wallet Request: Withdraw USDC on Mainnet ---

/// Exact eth_sendTransaction from a real wallet session:
/// to=0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2 (Aave LPv3, chain 1)
/// data=0x69328dec... (withdraw(address,uint256,address))
/// from=0xbf01daf454dce008d3e2bfd47d5e186f71477253
/// value=0x0
#[test]
fn real_wallet_withdraw_usdc_mainnet() {
    let descriptor = load_descriptor("aave-lpv3.json");
    let tokens = aave_token_source();

    let calldata = hex::decode(
        "69328dec\
         000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48\
         ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
         000000000000000000000000bf01daf454dce008d3e2bfd47d5e186f71477253",
    )
    .unwrap();

    let result = format_calldata_with_from(
        &descriptor,
        1,
        "0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2",
        &calldata,
        Some(&[0x00]),
        Some("0xbf01daf454dce008d3e2bfd47d5e186f71477253"),
        &tokens,
    )
    .unwrap();

    assert_eq!(result.intent, "Withdraw");
    assert_eq!(get_entry_value(&result, "Amount to withdraw"), "Max USDC");
    // Recipient should be the from address
    let to_value = get_entry_value(&result, "To recipient");
    assert!(
        to_value
            .to_lowercase()
            .contains("bf01daf454dce008d3e2bfd47d5e186f71477253"),
        "recipient should be the from address: {to_value}"
    );
    // Interpolated intent should use threshold/message formatting
    let interp = result.interpolated_intent.as_deref().unwrap();
    assert!(
        interp.contains("Max USDC"),
        "interpolated intent should contain 'Max USDC': {interp}"
    );
    assert!(
        interp.to_lowercase().contains("bf01daf454dce"),
        "interpolated intent should contain recipient: {interp}"
    );
}

/// Exact eth_sendTransaction: withdraw 0.1 USDC (100000 raw, 6 decimals) on mainnet.
/// Verifies interpolated intent renders formatted token amount, not raw integer.
#[test]
fn real_wallet_withdraw_0_1_usdc_mainnet() {
    let descriptor = load_descriptor("aave-lpv3.json");
    let tokens = aave_token_source();

    let calldata = hex::decode(
        "69328dec\
         000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48\
         00000000000000000000000000000000000000000000000000000000000186a0\
         000000000000000000000000bf01daf454dce008d3e2bfd47d5e186f71477253",
    )
    .unwrap();

    let result = format_calldata_with_from(
        &descriptor,
        1,
        "0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2",
        &calldata,
        Some(&[0x00]),
        Some("0xbf01daf454dce008d3e2bfd47d5e186f71477253"),
        &tokens,
    )
    .unwrap();

    assert_eq!(result.intent, "Withdraw");
    assert_eq!(get_entry_value(&result, "Amount to withdraw"), "0.1 USDC");

    // Interpolated intent must show "0.1 USDC", not raw "100000"
    let interp = result.interpolated_intent.as_deref().unwrap();
    assert!(
        interp.contains("0.1 USDC"),
        "interpolated intent should contain '0.1 USDC': {interp}"
    );
    assert!(
        !interp.contains("100000"),
        "interpolated intent should NOT contain raw '100000': {interp}"
    );
}

// --- FilesystemSource Test ---

#[tokio::test]
async fn filesystem_source_aave() {
    use erc7730::resolver::{DescriptorSource, FilesystemSource};

    let fixtures_dir = format!("{}/tests/fixtures", env!("CARGO_MANIFEST_DIR"));
    let source = FilesystemSource::from_directory(std::path::Path::new(&fixtures_dir)).unwrap();

    // LPv3 on mainnet
    let resolved = source
        .resolve_calldata(1, "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2")
        .await
        .unwrap();
    assert_eq!(resolved.chain_id, 1);

    // LPv3 on Base
    let resolved = source
        .resolve_calldata(8453, "0xA238Dd80C259a72e81d7e4664a9801593F98d1c5")
        .await
        .unwrap();
    assert_eq!(resolved.chain_id, 8453);

    // Not found
    let err = source
        .resolve_calldata(1, "0x0000000000000000000000000000000000000001")
        .await;
    assert!(err.is_err());
}
