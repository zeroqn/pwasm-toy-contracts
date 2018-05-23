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
use pwasm_abi_derive::eth_abi;
use pwasm_ethereum as eth;

use alloc::vec::Vec;

// Reserved storage addresses for special entries
static PROPOSAL_LEN_KEY: H256 = H256([
    2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
]);
static OWNER_KEY: H256 = H256([
    3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
]);
static WINNING_PROPOSAL_KEY: H256 = H256([
    4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
]);

mod eth_code {
    use parity_hash::H256;
    use pwasm_ethereum as eth;

    pub fn encode_bool(is_true: bool) -> [u8; 32] {
        let mut zero: [u8; 32] = Default::default();
        if is_true {
            zero[0] = 1
        }
        zero
    }

    pub fn decode_bool(value: [u8; 32]) -> bool {
        if value[0] == 1 {
            true
        } else {
            false
        }
    }

    pub fn read_bool(key: &H256) -> bool {
        decode_bool(eth::read(key))
    }

    pub fn write_bool(key: &H256, value: bool) {
        eth::write(key, &encode_bool(value));
    }
}

#[repr(u8)]
#[derive(Clone)]
pub enum VoterKey {
    Perm = 1,
    Voted = 2,
    ProposalId = 3,
}

impl VoterKey {
    fn key(&self, address: &Address) -> H256 {
        let mut key = H256::from(address);
        key[0] = self.clone() as u8;
        key
    }
}

#[repr(u8)]
#[derive(Clone)]
pub enum ProposalKey {
    Name = 1,
    VoteCount = 2,
}

impl ProposalKey {
    fn key(&self, proposal_id: U256) -> H256 {
        let mut key = H256::from(proposal_id);
        key[0] = self.clone() as u8;
        key
    }
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

    fn give_right_to_vote(&mut self, address: Address);

    fn vote(&mut self, proposal_id: U256);

    fn winning_proposal(&mut self) -> U256;

    #[constant]
    fn winner_name(&mut self) -> [u8; 32];
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
            // id starts from 1
            let key_id = idx + 1;
            eth::write(&ProposalKey::Name.key(key_id.into()), &name);
            eth::write(
                &ProposalKey::VoteCount.key(key_id.into()),
                &U256::from(0).into(),
            );
        }
    }

    fn is_voter(&mut self, address: Address) -> bool {
        eth_code::read_bool(&VoterKey::Perm.key(&address))
    }

    fn proposal_name(&mut self, proposal_id: U256) -> [u8; 32] {
        eth::read(&ProposalKey::Name.key(proposal_id))
    }

    fn proposal_vote_count(&mut self, proposal_id: U256) -> U256 {
        eth::read(&ProposalKey::VoteCount.key(proposal_id)).into()
    }

    fn voter_voted(&mut self, address: Address) -> bool {
        eth_code::read_bool(&VoterKey::Voted.key(&address))
    }

    fn voter_proposal_id(&mut self, address: Address) -> U256 {
        eth::read(&VoterKey::ProposalId.key(&address)).into()
    }

    fn give_right_to_vote(&mut self, address: Address) {
        let sender_hash: H256 = eth::sender().into();
        let owner_hash: H256 = eth::read(&OWNER_KEY).into();
        if sender_hash != owner_hash {
            panic!("only owner can give right");
        }

        eth_code::write_bool(&VoterKey::Perm.key(&address), true);
        eth::write(&VoterKey::Voted.key(&address), &U256::from(0).into());
        eth::write(&VoterKey::ProposalId.key(&address), &U256::from(0).into());
    }

    fn vote(&mut self, proposal_id: U256) {
        let sender = eth::sender();
        if !self.is_voter(sender) {
            panic!("only voter can vote");
        }

        if self.voter_voted(sender) {
            panic!("voter already vote");
        }

        let max_proposal_id: U256 = eth::read(&PROPOSAL_LEN_KEY).into();
        if proposal_id > max_proposal_id || proposal_id == 0.into() {
            panic!("proposal not found");
        }

        let vote_count: U256 = eth::read(&ProposalKey::VoteCount.key(proposal_id)).into();
        let new_vote_count: U256 = vote_count + 1.into();
        assert!(new_vote_count > vote_count);
        eth::write(
            &ProposalKey::VoteCount.key(proposal_id),
            &new_vote_count.into(),
        );

        eth_code::write_bool(&VoterKey::Voted.key(&eth::sender()), true);
        eth::write(
            &VoterKey::ProposalId.key(&eth::sender()),
            &proposal_id.into(),
        );
    }

    fn winning_proposal(&mut self) -> U256 {
        let max_proposal_id: U256 = eth::read(&PROPOSAL_LEN_KEY).into();
        let mut winning_proposal_id = U256::from(1);
        let mut winning_proposal_count = U256::from(0);
        for proposal_id in 1..(u64::from(max_proposal_id) + 1) {
            let vote_count: U256 =
                eth::read(&ProposalKey::VoteCount.key(proposal_id.into())).into();
            if vote_count > winning_proposal_count {
                winning_proposal_count = vote_count;
                winning_proposal_id = proposal_id.into();
            }
        }
        eth::write(&WINNING_PROPOSAL_KEY, &winning_proposal_id.into());
        winning_proposal_id
    }

    fn winner_name(&mut self) -> [u8; 32] {
        self.proposal_name(eth::read(&WINNING_PROPOSAL_KEY).into())
    }
}

#[cfg(test)]
extern crate pwasm_test;

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::str;
    use alloc::string::String;
    use alloc::string::ToString;
    use pwasm_test::{ext_reset, ext_update};

    fn encode_string(value: String) -> [u8; 32] {
        let mut eth_bytes: [u8; 32] = Default::default();
        let bytes = value.as_bytes();
        if bytes.len() > 32 {
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

    macro_rules! create_test_ballot {
        () => {{
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

            (ballot, owner_address, tester_address)
        }};
    }

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

        let names_len: U256 = eth::read(&PROPOSAL_LEN_KEY).into();
        assert_eq!(names_len, U256::from(3));

        let owner_hash = H256::from(eth::read(&OWNER_KEY));
        assert_eq!(owner_hash, H256::from(owner_address));

        for (id, name) in [(1, "triss"), (2, "yennefer"), (3, "ciri")].iter() {
            let id: U256 = U256::from(*id);
            let saved_name = decode_string(eth::read(&ProposalKey::Name.key(id)));
            assert_eq!(saved_name, name.to_string());
            let vote_count: U256 = eth::read(&ProposalKey::VoteCount.key(id)).into();
            assert_eq!(vote_count, U256::from(0));
        }
    }

    #[test]
    #[should_panic]
    fn should_panic_on_giving_voter_right_without_owner_permission() {
        let (mut ballot, ..) = create_test_ballot!();
        let tester = Address::from("0xdb6fd484cfa46eeeb73c71edee823e4812f9e2e2");
        assert!(!ballot.is_voter(tester));

        ext_update(|e| e.sender(tester.clone()));
        ballot.give_right_to_vote(tester);
    }

    #[test]
    fn should_check_whether_a_address_is_voter() {
        let (mut ballot, owner, _) = create_test_ballot!();
        let tester_address = Address::from("0xdb6fd484cfa46eeeb73c71edee823e4812f9e2e2");

        assert!(!ballot.is_voter(tester_address));

        ext_update(|e| e.sender(owner.clone()));
        ballot.give_right_to_vote(tester_address);
        assert!(ballot.is_voter(tester_address));
    }

    #[test]
    fn should_return_right_proposal_name() {
        let (mut ballot, ..) = create_test_ballot!();

        for (id, name) in [(1, "triss"), (2, "yennefer"), (3, "ciri")].iter() {
            let stored_name = ballot.proposal_name(U256::from(*id));
            assert_eq!(decode_string(stored_name), *name);
        }
    }

    #[test]
    fn should_return_right_proposal_vote_count() {
        let (mut ballot, ..) = create_test_ballot!();

        for id in 1..4 {
            let count = ballot.proposal_vote_count(U256::from(id));
            assert_eq!(count, U256::from(0));
        }
    }

    #[test]
    fn should_return_whether_a_voter_already_voted() {
        let (mut ballot, _, voter) = create_test_ballot!();

        ext_update(|e| e.sender(voter.clone()));
        assert!(!ballot.voter_voted(voter));
        ballot.vote(1.into());
        assert!(ballot.voter_voted(voter));
    }

    #[test]
    fn shoudl_return_voter_proposal_id() {
        let (mut ballot, _, voter) = create_test_ballot!();

        ext_update(|e| e.sender(voter.clone()));
        assert_eq!(ballot.voter_proposal_id(voter), U256::from(0));
        ballot.vote(2.into());
        assert_eq!(ballot.voter_proposal_id(voter), U256::from(2));
    }

    #[test]
    fn should_voter_vote() {
        let (mut ballot, owner, voter) = create_test_ballot!();
        let voter2 = Address::from("0xdb6fd484cfa46eeeb73c71edee823e4812f9e2e2");

        ext_update(|e| e.sender(owner.clone()));
        ballot.give_right_to_vote(voter2);

        for id in 1..4 {
            assert_eq!(ballot.proposal_vote_count(id.into()), U256::from(0));
        }
        assert!(!ballot.voter_voted(voter));
        assert!(!ballot.voter_voted(voter2));
        assert_eq!(ballot.voter_proposal_id(voter), U256::from(0));
        assert_eq!(ballot.voter_proposal_id(voter2), U256::from(0));

        ext_update(|e| e.sender(voter.clone()));
        ballot.vote(1.into());
        assert_eq!(ballot.proposal_vote_count(1.into()), U256::from(1));
        assert!(ballot.voter_voted(voter));
        assert_eq!(ballot.voter_proposal_id(voter), U256::from(1));

        ext_update(|e| e.sender(voter2.clone()));
        ballot.vote(U256::from(2));
        assert_eq!(ballot.proposal_vote_count(U256::from(2)), U256::from(1));
        assert!(ballot.voter_voted(voter2));
        assert_eq!(ballot.voter_proposal_id(voter2), U256::from(2));
    }

    #[test]
    #[should_panic]
    fn should_panic_if_vote_by_non_voter() {
        let (mut ballot, ..) = create_test_ballot!();
        let tester = Address::from("0xdb6fd484cfa46eeeb73c71edee823e4812f9e2e2");

        ext_update(|e| e.sender(tester.clone()));
        ballot.vote(1.into());
    }

    #[test]
    #[should_panic]
    fn should_panic_if_voter_already_voted() {
        let (mut ballot, _owner, voter) = create_test_ballot!();

        ext_update(|e| e.sender(voter.clone()));
        ballot.vote(1.into());
        ballot.vote(2.into());
    }

    #[test]
    #[should_panic]
    fn should_panic_using_bad_proposal_id() {
        let (mut ballot, _owner, voter) = create_test_ballot!();

        ext_update(|e| e.sender(voter.clone()));
        ballot.vote(99.into());
    }

    #[test]
    #[should_panic]
    fn should_panic_using_proposal_id_is_zero() {
        let (mut ballot, _owner, voter) = create_test_ballot!();

        ext_update(|e| e.sender(voter.clone()));
        ballot.vote(0.into());
    }

    #[test]
    fn should_declare_winning_proposal() {
        let (mut ballot, _, voter) = create_test_ballot!();

        ext_update(|e| e.sender(voter.clone()));
        ballot.vote(2.into());

        assert_eq!(ballot.proposal_vote_count(U256::from(2)), U256::from(1));
        assert!(ballot.voter_voted(voter));
        assert_eq!(ballot.voter_proposal_id(voter), U256::from(2));

        assert_eq!(ballot.winning_proposal(), U256::from(2));
        assert_eq!(U256::from(eth::read(&WINNING_PROPOSAL_KEY)), U256::from(2));

        assert_eq!(decode_string(ballot.winner_name()), "yennefer");
    }
}
