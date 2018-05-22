#![no_std]
#![allow(non_snake_case)]
#![feature(alloc)]
#![feature(proc_macro)]

extern crate alloc;
extern crate bigint;
extern crate parity_hash;
extern crate pwasm_abi;
extern crate pwasm_abi_derive;
extern crate pwasm_ethereum;
extern crate pwasm_std;

use bigint::U256;
use parity_hash::{Address, H256};
use pwasm_abi::eth::{AbiType, Error as AbiError, Sink, Stream};
use pwasm_abi_derive::eth_abi;
use pwasm_ethereum as eth;

use alloc::str;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;

#[repr(u8)]
pub enum VoterKeyNamespace {
    VoterSelf = 1,
    Voted = 2,
    VoteProposalId = 3,
}

#[repr(u8)]
pub enum ProposalKeyNamespace {
    Name = 1,
    VoteCount = 2,
}

#[eth_abi(Endpoint, Client)]
pub trait BallotContract {
    fn constructor(&mut self, proposal_names: Vec<[u8; 32]>);

    #[constant]
    fn is_voter(&mut self, address: Address) -> bool;

    #[constant]
    fn proposal_name(&mut self, proposal_id: U256) -> [u8; 32];

    #[constant]
    fn proposal_vote_count(&mut self, proposal_id: U256) -> U256;

    #[constant]
    fn voter_voted(&mut self, address: Address) -> bool;

    #[constant]
    fn voter_proposal_id(&mut self, address: Address) -> U256;

    fn give_right_to_vote(&mut self, voter: Address);

    fn vote(&mut self, proposal_id: U256);

    fn winning_proposal(&mut self) -> U256;

    #[constant]
    fn winner_name(&mut self) -> [u8; 32];
}

static KEY_OFFSET: usize = 5;
static PROPOSAL_LEN_KEY: H256 = H256([
    2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
]);
static OWNER_KEY: H256 = H256([
    3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
]);
static WINNING_PROPOSAL_KEY: H256 = H256([
    4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
]);

fn encode_bool(is_true: bool) -> [u8; 32] {
    let mut zero: [u8; 32] = Default::default();
    if is_true {
        zero[0] = 1
    }
    zero
}

fn decode_bool(value: [u8; 32]) -> bool {
    if value[0] == 1 {
        true
    } else {
        false
    }
}

fn read_eth_bool(key: &H256) -> bool {
    decode_bool(eth::read(key))
}

fn write_eth_bool(key: &H256, value: bool) {
    eth::write(key, &encode_bool(value));
}

fn read_eth_u256(key: &H256) -> U256 {
    eth::read(key).into()
}

fn write_eth_u256(key: &H256, value: U256) {
    eth::write(key, &value.into());
}

fn encode_string(value: String) -> [u8; 32] {
    let mut eth_bytes: [u8; 32] = Default::default();
    let bytes = value.as_bytes();
    if (bytes.len() > 32) {
        panic!("Only 32 bytes long string is support right now for simplicity");
    }
    eth_bytes[..bytes.len()].copy_from_slice(&bytes);
    eth_bytes
}

fn decode_string(value: [u8; 32]) -> String {
    str::from_utf8(&value)
        .expect("Invalid string")
        .trim_right_matches('\u{0}')
        .to_string()
}

fn read_eth_string(key: &H256) -> String {
    decode_string(eth::read(key))
}

fn write_eth_string(key: &H256, value: String) {
    eth::write(key, &encode_string(value));
}

fn voter_key(address: &Address, key_ns: VoterKeyNamespace) -> H256 {
    let mut key = H256::from(address);
    key[0] = key_ns as u8;
    key
}

fn proposal_key(id: U256, key_ns: ProposalKeyNamespace) -> H256 {
    let mut key = H256::from(id);
    key[0] = key_ns as u8;
    key
}

pub struct BallotContractInstance;

impl BallotContract for BallotContractInstance {
    fn constructor(&mut self, proposal_names: Vec<[u8; 32]>) {
        let sender = eth::sender();
        eth::write(
            &PROPOSAL_LEN_KEY,
            &H256::from(proposal_names.len() as u64).into(),
        );
        eth::write(&OWNER_KEY, &H256::from(sender).into());
        for (idx, name) in proposal_names.iter().enumerate() {
            let key_id = idx + KEY_OFFSET + 1;
            let key = proposal_key(U256::from(key_id), ProposalKeyNamespace::Name);
            eth::write(&key, &name);
            let key = proposal_key(U256::from(key_id), ProposalKeyNamespace::VoteCount);
            write_eth_u256(&key, U256::from(0));
        }
    }

    fn is_voter(&mut self, address: Address) -> bool {
        let key = voter_key(&address, VoterKeyNamespace::VoterSelf);
        read_eth_bool(&key)
    }

    fn proposal_name(&mut self, proposal_id: U256) -> [u8; 32] {
        let key_id = proposal_id + U256::from(KEY_OFFSET as u64);
        eth::read(&proposal_key(key_id, ProposalKeyNamespace::Name))
    }

    fn proposal_vote_count(&mut self, proposal_id: U256) -> U256 {
        let key_id = proposal_id + U256::from(KEY_OFFSET as u64);
        eth::read(&proposal_key(key_id, ProposalKeyNamespace::VoteCount)).into()
    }

    fn voter_voted(&mut self, address: Address) -> bool {
        let key = voter_key(&address, VoterKeyNamespace::Voted);
        decode_bool(eth::read(&key))
    }

    fn voter_proposal_id(&mut self, address: Address) -> U256 {
        let key = voter_key(&address, VoterKeyNamespace::VoteProposalId);
        eth::read(&key).into()
    }

    fn give_right_to_vote(&mut self, voter: Address) {
        let sender = H256::from(eth::sender());
        let owner = H256::from(eth::read(&OWNER_KEY));
        if sender != owner {
            panic!("only owner can give right");
        }

        let key = voter_key(&voter, VoterKeyNamespace::VoterSelf);
        write_eth_bool(&key, true);
    }

    fn vote(&mut self, proposal_id: U256) {
        let sender = eth::sender();
        if !self.is_voter(sender) {
            panic!("only voter can vote");
        }

        let max_proposal_id: U256 = eth::read(&PROPOSAL_LEN_KEY).into();
        if proposal_id > max_proposal_id {
            panic!("proposal not found");
        }

        let proposal_key_id = proposal_id + U256::from(KEY_OFFSET);
        let proposal_key = proposal_key(proposal_key_id, ProposalKeyNamespace::VoteCount);
        let vote_count = read_eth_u256(&proposal_key);
        write_eth_u256(&proposal_key, vote_count + U256::from(1));

        write_eth_bool(&voter_key(&eth::sender(), VoterKeyNamespace::Voted), true);
        write_eth_u256(
            &voter_key(&eth::sender(), VoterKeyNamespace::VoteProposalId),
            proposal_id,
        );
    }

    fn winning_proposal(&mut self) -> U256 {
        let max_proposal_id: U256 = eth::read(&PROPOSAL_LEN_KEY).into();
        let mut winning_proposal_id = U256::from(1);
        let mut winning_proposal_count = U256::from(0);
        for proposal_id in 1..(u64::from(max_proposal_id) + 1) {
            let proposal_key_id = U256::from(proposal_id) + U256::from(KEY_OFFSET);
            let proposal_key = proposal_key(proposal_key_id, ProposalKeyNamespace::VoteCount);
            let vote_count = read_eth_u256(&proposal_key);
            if vote_count > winning_proposal_count {
                winning_proposal_count = vote_count;
                winning_proposal_id = U256::from(proposal_id);
            }
        }
        write_eth_u256(&WINNING_PROPOSAL_KEY, winning_proposal_id.into());
        winning_proposal_id
    }

    fn winner_name(&mut self) -> [u8; 32] {
        let proposal_id: U256 = read_eth_u256(&WINNING_PROPOSAL_KEY).into();
        self.proposal_name(proposal_id)
    }
}

#[cfg(test)]
extern crate pwasm_test;

#[cfg(test)]
mod tests {
    use super::*;
    use pwasm_test::{ext_get, ext_reset, ext_update, External};

    #[test]
    fn should_create_ballot() {
        let mut ballot = BallotContractInstance {};
        let names = [
            encode_string("triss".to_string()),
            encode_string("yennefer".to_string()),
            encode_string("ciri".to_string()),
        ].to_vec();

        let owner_address = Address::from("0xea674fdde714fd979de3edf0f56aa9716b898ec8");
        ext_reset(|e| e.sender(owner_address.clone()));

        ballot.constructor(names);

        let names_len = read_eth_u256(&PROPOSAL_LEN_KEY);
        assert_eq!(names_len, U256::from(3));

        let owner_hash = H256::from(eth::read(&OWNER_KEY));
        assert_eq!(owner_hash, H256::from(owner_address));

        for (id, name) in [(1, "triss"), (2, "yennefer"), (3, "ciri")].iter() {
            let name_key = proposal_key(U256::from(id + KEY_OFFSET), ProposalKeyNamespace::Name);
            let saved_name = read_eth_string(&name_key);
            assert_eq!(saved_name, name.to_string());

            let count_key =
                proposal_key(U256::from(id + KEY_OFFSET), ProposalKeyNamespace::VoteCount);
            let vote_count = read_eth_u256(&count_key);
            assert_eq!(vote_count, U256::from(0));
        }
    }

    #[test]
    fn should_check_whether_a_address_is_voter() {
        let mut ballot = BallotContractInstance {};
        let names = [
            encode_string("triss".to_string()),
            encode_string("yennefer".to_string()),
            encode_string("ciri".to_string()),
        ].to_vec();

        let owner_address = Address::from("0xea674fdde714fd979de3edf0f56aa9716b898ec8");
        let tester_address = Address::from("0xdb6fd484cfa46eeeb73c71edee823e4812f9e2e1");

        ext_reset(|e| e.sender(owner_address.clone()));

        ballot.constructor(names);
        assert!(!ballot.is_voter(tester_address));

        ballot.give_right_to_vote(tester_address);
        assert!(ballot.is_voter(tester_address));
    }

    #[test]
    fn should_return_right_proposal_name() {
        let mut ballot = BallotContractInstance {};
        let names = [
            encode_string("triss".to_string()),
            encode_string("yennefer".to_string()),
            encode_string("ciri".to_string()),
        ].to_vec();

        let owner_address = Address::from("0xea674fdde714fd979de3edf0f56aa9716b898ec8");

        ext_reset(|e| e.sender(owner_address.clone()));

        ballot.constructor(names);
        for (id, name) in [(1, "triss"), (2, "yennefer"), (3, "ciri")].iter() {
            let stored_name = ballot.proposal_name(U256::from(*id));
            assert_eq!(decode_string(stored_name), *name);
        }
    }

    #[test]
    fn should_return_right_proposal_vote_count() {
        let mut ballot = BallotContractInstance {};
        let names = [
            encode_string("triss".to_string()),
            encode_string("yennefer".to_string()),
            encode_string("ciri".to_string()),
        ].to_vec();

        let owner_address = Address::from("0xea674fdde714fd979de3edf0f56aa9716b898ec8");

        ext_reset(|e| e.sender(owner_address.clone()));

        ballot.constructor(names);
        for id in 1..4 {
            let count = ballot.proposal_vote_count(U256::from(id));
            assert_eq!(count, U256::from(0));
        }
    }

    #[test]
    fn should_return_whether_a_voter_already_voted() {
        let mut ballot = BallotContractInstance {};
        let names = [
            encode_string("triss".to_string()),
            encode_string("yennefer".to_string()),
            encode_string("ciri".to_string()),
        ].to_vec();

        let owner_address = Address::from("0xea674fdde714fd979de3edf0f56aa9716b898ec8");
        let tester_address = Address::from("0xdb6fd484cfa46eeeb73c71edee823e4812f9e2e1");

        ext_reset(|e| e.sender(owner_address.clone()));

        ballot.constructor(names);
        ballot.give_right_to_vote(tester_address);

        assert!(!ballot.voter_voted(tester_address));
    }

    #[test]
    fn shoudl_return_voter_proposal_id() {
        let mut ballot = BallotContractInstance {};
        let names = [
            encode_string("triss".to_string()),
            encode_string("yennefer".to_string()),
            encode_string("ciri".to_string()),
        ].to_vec();

        let owner_address = Address::from("0xea674fdde714fd979de3edf0f56aa9716b898ec8");
        let tester_address = Address::from("0xdb6fd484cfa46eeeb73c71edee823e4812f9e2e1");

        ext_reset(|e| e.sender(owner_address.clone()));

        ballot.constructor(names);
        ballot.give_right_to_vote(tester_address);

        assert_eq!(ballot.voter_proposal_id(tester_address), U256::from(0));
    }

    #[test]
    fn should_voter_vote() {
        let mut ballot = BallotContractInstance {};
        let names = [
            encode_string("triss".to_string()),
            encode_string("yennefer".to_string()),
            encode_string("ciri".to_string()),
        ].to_vec();

        let owner_address = Address::from("0xea674fdde714fd979de3edf0f56aa9716b898ec8");
        let tester_address = Address::from("0xdb6fd484cfa46eeeb73c71edee823e4812f9e2e1");
        let tester2_address = Address::from("0xdb6fd484cfa46eeeb73c71edee823e4812f9e2e1");

        ext_reset(|e| e.sender(owner_address.clone()));

        ballot.constructor(names);
        ballot.give_right_to_vote(tester_address);
        ballot.give_right_to_vote(tester2_address);

        ext_update(|e| e.sender(tester_address.clone()));

        ballot.vote(U256::from(1));
        assert_eq!(ballot.proposal_vote_count(U256::from(1)), U256::from(1));
        assert!(ballot.voter_voted(tester_address));
        assert_eq!(ballot.voter_proposal_id(tester_address), U256::from(1));

        ext_update(|e| e.sender(tester2_address.clone()));

        ballot.vote(U256::from(2));
        assert_eq!(ballot.proposal_vote_count(U256::from(2)), U256::from(1));
        assert!(ballot.voter_voted(tester2_address));
        assert_eq!(ballot.voter_proposal_id(tester2_address), U256::from(2));

        assert_eq!(ballot.proposal_vote_count(U256::from(3)), U256::from(0));
    }

    #[test]
    fn should_declare_winning_proposal() {
        let mut ballot = BallotContractInstance {};
        let names = [
            encode_string("triss".to_string()),
            encode_string("yennefer".to_string()),
            encode_string("ciri".to_string()),
        ].to_vec();

        let owner_address = Address::from("0xea674fdde714fd979de3edf0f56aa9716b898ec8");
        let tester_address = Address::from("0xdb6fd484cfa46eeeb73c71edee823e4812f9e2e1");

        ext_reset(|e| e.sender(owner_address.clone()));

        ballot.constructor(names);
        ballot.give_right_to_vote(tester_address);

        ext_update(|e| e.sender(tester_address.clone()));

        ballot.vote(U256::from(2));
        assert_eq!(ballot.proposal_vote_count(U256::from(2)), U256::from(1));
        assert!(ballot.voter_voted(tester_address));
        assert_eq!(ballot.voter_proposal_id(tester_address), U256::from(2));

        assert_eq!(ballot.winning_proposal(), U256::from(2));
        assert_eq!(read_eth_u256(&WINNING_PROPOSAL_KEY), 2.into());

        assert_eq!(decode_string(ballot.winner_name()), "yennefer");
    }
}
