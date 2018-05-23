#!/bin/bash

cargo build --release --target wasm32-unknown-unknown
wasm-build ./target/ pwasm_toy_ballot --target=wasm32-unknown-unknown --final=ballot --save-raw=./target/ballot-deployed.wasm

cp ./target/*.wasm ./compiled
cp ./target/json/* ./compiled
