# zero-knowledge-hackathon
creating a zero knowledge proof using zokrates
given below are the steps to create proofs to verify someones age eligibilty
## step1: create a .zok file where we have a private field that consist of our to be hidden data and a public field to which we compare for eligibility.
## step2: run the following commands
### zokrates compile -i factor.zok
### zokrates setup
### zokrates compute-witness -a value_a value_c
### zokrates generate-proof
### zokrates export-verifier

