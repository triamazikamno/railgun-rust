//! Encoder and decoder for one weiroll script: deposit an account's whole
//! balance of a token into Across.
//!
//! This is not a weiroll planner. [`BalanceDeposit::encode`] emits one fixed
//! script and [`BalanceDeposit::decode`] accepts only that script. The weiroll
//! executor address is chain profile data supplied by callers.
//!
//! The VM runs `execute(bytes32[] commands, bytes[] state)`. A command is one
//! 32-byte word:
//!
//! ```text
//! selector (4) | flags (1) | input indices (6) | output index (1) | target (20)
//! ```
//!
//! The low two bits of `flags` are the call type: 0 delegatecall, 1 call,
//! 2 staticcall, 3 call with value. With flag `0x40` the command is extended:
//! its six in-word index bytes are zero and the next word of `commands` holds
//! 32 input index bytes instead.
//!
//! An index byte is a position in `state`. Index `0xff` ends the argument
//! list, and as an output index it discards the return value. A static state
//! element is exactly one 32-byte ABI word, and a static return value is
//! written to its output element as one word. An index with bit `0x80` set
//! names a dynamic element, which holds the ABI encoding of the value without
//! its leading offset word. For `bytes` that is a length word followed by the
//! data, zero-padded to a multiple of 32 bytes.

use alloy::primitives::{Address, B256, Bytes, U256};
use alloy::sol;
use alloy::sol_types::{SolCall, SolValue};
use thiserror::Error;

use super::across::{MulticallHandler, SpokePool, bytes32_to_address, private_delivery_message};
use super::executor::AcrossPrivateDelivery;
use super::railgun::approveCall;
use super::swap_math::SwapMath;

sol! {
    interface WeirollExecutor {
        function execute(bytes32[] commands, bytes[] state) payable returns (bytes[]);
    }

    interface IERC20 {
        function balanceOf(address account) view returns (uint256);
    }
}

const FLAG_CALL: u8 = 0x01;
const FLAG_STATICCALL: u8 = 0x02;
const FLAG_EXTENDED: u8 = 0x40;
const INDEX_DYNAMIC: u8 = 0x80;
const INDEX_END: u8 = 0xff;

// State layout of the script. Every element but `MESSAGE` is static.
//
// | index | element               | set by    | read by                      |
// |-------|-----------------------|-----------|------------------------------|
// | 0     | proxy                 | encode    | `balanceOf`                  |
// | 1     | destination_min       | encode    | `scale` numerator            |
// | 2     | buy_amount            | encode    | `scale` denominator          |
// | 3     | spoke_pool            | encode    | `approve` spender            |
// | 4     | depositor             | encode    | `depositV3`                  |
// | 5     | handler               | encode    | `depositV3` recipient        |
// | 6     | input_token           | encode    | `depositV3`                  |
// | 7     | output_token          | encode    | `depositV3`                  |
// | 8     | destination_chain_id  | encode    | `depositV3`                  |
// | 9     | exclusive_relayer     | encode    | `depositV3`                  |
// | 10    | quote_timestamp       | encode    | `depositV3`                  |
// | 11    | fill_deadline         | encode    | `depositV3`                  |
// | 12    | exclusivity_parameter | encode    | `depositV3`                  |
// | 13    | message (dynamic)     | encode    | `depositV3`                  |
// | 14    | balance               | command 0 | `scale`, `approve`, `depositV3` input amount |
// | 15    | output                | command 1 | `depositV3` output amount    |
//
// `balance` and `output` are empty until their command writes them.
const PROXY: u8 = 0;
const DESTINATION_MIN: u8 = 1;
const BUY_AMOUNT: u8 = 2;
const SPOKE_POOL: u8 = 3;
const DEPOSITOR: u8 = 4;
const HANDLER: u8 = 5;
const INPUT_TOKEN: u8 = 6;
const OUTPUT_TOKEN: u8 = 7;
const DESTINATION_CHAIN_ID: u8 = 8;
const EXCLUSIVE_RELAYER: u8 = 9;
const QUOTE_TIMESTAMP: u8 = 10;
const FILL_DEADLINE: u8 = 11;
const EXCLUSIVITY_PARAMETER: u8 = 12;
const MESSAGE: u8 = 13;
const BALANCE: u8 = 14;
const OUTPUT: u8 = 15;
const STATE_LEN: usize = 16;

const COMMAND_COUNT: usize = 5;
/// The command whose target is the math contract.
const SCALE_COMMAND: usize = 1;

/// The one script: deposit the proxy's whole balance of `input_token` into Across.
///
/// 1. `balance = input_token.balanceOf(proxy)`, a staticcall.
/// 2. `output = math.scale(balance, destination_min, buy_amount)`.
/// 3. `input_token.approve(spoke_pool, balance)`.
/// 4. `spoke_pool.depositV3(...)` of `balance` for `output`, with
///    `delivery.handler` as the recipient and the [`private_delivery_message`]
///    for `delivery` and `output_token` as the message.
///
/// The output amount keeps the ratio `destination_min / buy_amount`, so a
/// balance above `buy_amount` raises it in proportion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BalanceDeposit {
    /// The cow-shed proxy that runs the script by delegatecall.
    pub proxy: Address,
    /// The `SwapMath` contract.
    pub math: Address,
    pub spoke_pool: Address,
    /// `scale` denominator: the order's buy amount.
    pub buy_amount: U256,
    /// `scale` numerator: the approved destination minimum.
    pub destination_min: U256,
    /// The Public account. Across refunds it.
    pub depositor: Address,
    /// The bought token.
    pub input_token: Address,
    pub output_token: Address,
    pub destination_chain_id: u64,
    pub exclusive_relayer: Address,
    pub quote_timestamp: u32,
    pub fill_deadline: u32,
    pub exclusivity_parameter: u32,
    pub delivery: AcrossPrivateDelivery,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum WeirollError {
    #[error("calldata is not a weiroll `execute` call")]
    NotExecute,
    #[error("balance-deposit script has 5 command words, got {0}")]
    CommandCount(usize),
    #[error("command word {0} is not the balance-deposit script's")]
    Command(usize),
    #[error("balance-deposit script has 16 state elements, got {0}")]
    StateLength(usize),
    #[error("state element {0} is malformed")]
    StateElement(usize),
    #[error("deposit message is not the private-delivery message")]
    NotPrivateDeliveryMessage,
    #[error("buy amount must be nonzero; it is the `scale` denominator")]
    ZeroBuyAmount,
}

impl BalanceDeposit {
    /// `WeirollExecutor.execute(commands, state)` calldata. Errors when
    /// `buy_amount` is zero.
    pub fn encode(&self) -> Result<Bytes, WeirollError> {
        if self.buy_amount.is_zero() {
            return Err(WeirollError::ZeroBuyAmount);
        }
        let message = private_delivery_message(
            self.delivery.handler,
            self.output_token,
            self.delivery.destination_executor,
            self.delivery.shield_multicall.clone(),
            self.delivery.fallback,
        );
        // In index order, see the layout table above.
        let state = vec![
            address_element(self.proxy),
            uint_element(self.destination_min),
            uint_element(self.buy_amount),
            address_element(self.spoke_pool),
            address_element(self.depositor),
            address_element(self.delivery.handler),
            address_element(self.input_token),
            address_element(self.output_token),
            uint_element(U256::from(self.destination_chain_id)),
            address_element(self.exclusive_relayer),
            uint_element(U256::from(self.quote_timestamp)),
            uint_element(U256::from(self.fill_deadline)),
            uint_element(U256::from(self.exclusivity_parameter)),
            bytes_element(&message),
            Bytes::new(),
            Bytes::new(),
        ];
        Ok(WeirollExecutor::executeCall {
            commands: commands(self.input_token, self.math, self.spoke_pool).to_vec(),
            state,
        }
        .abi_encode()
        .into())
    }

    /// The script `calldata` runs, or an error if it is not exactly the shape
    /// [`Self::encode`] emits.
    pub fn decode(calldata: &[u8]) -> Result<Self, WeirollError> {
        let WeirollExecutor::executeCall { commands, state } =
            WeirollExecutor::executeCall::abi_decode(calldata)
                .map_err(|_| WeirollError::NotExecute)?;
        if commands.len() != COMMAND_COUNT {
            return Err(WeirollError::CommandCount(commands.len()));
        }
        if state.len() != STATE_LEN {
            return Err(WeirollError::StateLength(state.len()));
        }
        for index in [BALANCE, OUTPUT] {
            if !state[usize::from(index)].is_empty() {
                return Err(malformed(index));
            }
        }

        let buy_amount = uint(&state, BUY_AMOUNT)?;
        if buy_amount.is_zero() {
            return Err(WeirollError::ZeroBuyAmount);
        }
        let handler = address(&state, HANDLER)?;
        let output_token = address(&state, OUTPUT_TOKEN)?;
        let message =
            bytes_element_data(&state[usize::from(MESSAGE)]).ok_or_else(|| malformed(MESSAGE))?;
        let deposit = Self {
            proxy: address(&state, PROXY)?,
            math: Address::from_slice(&commands[SCALE_COMMAND][12..]),
            spoke_pool: address(&state, SPOKE_POOL)?,
            buy_amount,
            destination_min: uint(&state, DESTINATION_MIN)?,
            depositor: address(&state, DEPOSITOR)?,
            input_token: address(&state, INPUT_TOKEN)?,
            output_token,
            destination_chain_id: u64::try_from(uint(&state, DESTINATION_CHAIN_ID)?)
                .map_err(|_| malformed(DESTINATION_CHAIN_ID))?,
            exclusive_relayer: address(&state, EXCLUSIVE_RELAYER)?,
            quote_timestamp: uint32(&state, QUOTE_TIMESTAMP)?,
            fill_deadline: uint32(&state, FILL_DEADLINE)?,
            exclusivity_parameter: uint32(&state, EXCLUSIVITY_PARAMETER)?,
            delivery: decode_delivery(message, handler, output_token)
                .ok_or(WeirollError::NotPrivateDeliveryMessage)?,
        };

        let expected = self::commands(deposit.input_token, deposit.math, deposit.spoke_pool);
        match commands
            .iter()
            .zip(expected)
            .position(|(got, want)| *got != want)
        {
            Some(index) => Err(WeirollError::Command(index)),
            None => Ok(deposit),
        }
    }
}

/// The five command words of the script.
fn commands(input_token: Address, math: Address, spoke_pool: Address) -> [B256; COMMAND_COUNT] {
    // `depositV3` takes 12 arguments, more than the six a command word holds.
    let mut deposit_inputs = [INDEX_END; 32];
    deposit_inputs[..12].copy_from_slice(&[
        DEPOSITOR,
        HANDLER,
        INPUT_TOKEN,
        OUTPUT_TOKEN,
        BALANCE,
        OUTPUT,
        DESTINATION_CHAIN_ID,
        EXCLUSIVE_RELAYER,
        QUOTE_TIMESTAMP,
        FILL_DEADLINE,
        EXCLUSIVITY_PARAMETER,
        MESSAGE | INDEX_DYNAMIC,
    ]);
    [
        command(
            IERC20::balanceOfCall::SELECTOR,
            FLAG_STATICCALL,
            [PROXY, INDEX_END, INDEX_END, INDEX_END, INDEX_END, INDEX_END],
            BALANCE,
            input_token,
        ),
        command(
            SwapMath::scaleCall::SELECTOR,
            FLAG_CALL,
            [
                BALANCE,
                DESTINATION_MIN,
                BUY_AMOUNT,
                INDEX_END,
                INDEX_END,
                INDEX_END,
            ],
            OUTPUT,
            math,
        ),
        command(
            approveCall::SELECTOR,
            FLAG_CALL,
            [
                SPOKE_POOL, BALANCE, INDEX_END, INDEX_END, INDEX_END, INDEX_END,
            ],
            INDEX_END,
            input_token,
        ),
        command(
            SpokePool::depositV3Call::SELECTOR,
            FLAG_CALL | FLAG_EXTENDED,
            [0; 6],
            INDEX_END,
            spoke_pool,
        ),
        B256::new(deposit_inputs),
    ]
}

fn command(selector: [u8; 4], flags: u8, inputs: [u8; 6], output: u8, target: Address) -> B256 {
    let mut word = [0u8; 32];
    word[..4].copy_from_slice(&selector);
    word[4] = flags;
    word[5..11].copy_from_slice(&inputs);
    word[11] = output;
    word[12..].copy_from_slice(target.as_slice());
    B256::new(word)
}

fn address_element(address: Address) -> Bytes {
    Bytes::copy_from_slice(address.into_word().as_slice())
}

fn uint_element(value: U256) -> Bytes {
    Bytes::copy_from_slice(&value.to_be_bytes::<32>())
}

/// A dynamic `bytes` state element: the length word, then the padded data.
fn bytes_element(data: &[u8]) -> Bytes {
    let mut element = U256::from(data.len()).to_be_bytes::<32>().to_vec();
    element.extend_from_slice(data);
    element.resize(32 + data.len().next_multiple_of(32), 0);
    element.into()
}

/// The data of a dynamic `bytes` state element, or `None` unless the element
/// is exactly what [`bytes_element`] emits for it.
fn bytes_element_data(element: &[u8]) -> Option<&[u8]> {
    let (length, data) = element.split_first_chunk::<32>()?;
    let length = usize::try_from(U256::from_be_bytes(*length)).ok()?;
    (data.len() == length.checked_next_multiple_of(32)?
        && data[length..].iter().all(|byte| *byte == 0))
    .then(|| &data[..length])
}

fn malformed(index: u8) -> WeirollError {
    WeirollError::StateElement(usize::from(index))
}

fn word(state: &[Bytes], index: u8) -> Result<B256, WeirollError> {
    let element: &[u8] = &state[usize::from(index)];
    B256::try_from(element).map_err(|_| malformed(index))
}

fn uint(state: &[Bytes], index: u8) -> Result<U256, WeirollError> {
    Ok(U256::from_be_bytes(word(state, index)?.0))
}

fn uint32(state: &[Bytes], index: u8) -> Result<u32, WeirollError> {
    u32::try_from(uint(state, index)?).map_err(|_| malformed(index))
}

fn address(state: &[Bytes], index: u8) -> Result<Address, WeirollError> {
    bytes32_to_address(word(state, index)?).ok_or_else(|| malformed(index))
}

/// The delivery `message` encodes for a fill of `output_token` to `handler`,
/// or `None` unless it is the canonical [`private_delivery_message`] for it.
fn decode_delivery(
    message: &[u8],
    handler: Address,
    output_token: Address,
) -> Option<AcrossPrivateDelivery> {
    let instructions = MulticallHandler::Instructions::abi_decode(message).ok()?;
    let [drain, shield] = instructions.calls.as_slice() else {
        return None;
    };
    if drain.target != handler || !drain.value.is_zero() || !shield.value.is_zero() {
        return None;
    }
    let drained = MulticallHandler::drainLeftoverTokensCall::abi_decode(&drain.callData).ok()?;
    if drained.token != output_token || shield.target != drained.destination {
        return None;
    }
    let fallback = instructions.fallbackRecipient;
    let delivery = AcrossPrivateDelivery {
        handler,
        destination_executor: drained.destination,
        shield_multicall: shield.callData.clone(),
        fallback: (!fallback.is_zero()).then_some(fallback),
    };
    let canonical = private_delivery_message(
        handler,
        output_token,
        delivery.destination_executor,
        delivery.shield_multicall.clone(),
        delivery.fallback,
    );
    (*canonical == *message).then_some(delivery)
}

#[cfg(test)]
mod tests;
