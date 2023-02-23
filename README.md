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

## the third directory :
### This implementation demonstrates the scenenario of password verification when the user wants to convince the other party of their authenticity. But at the same time he cannot reveal his password to the other party, hence zero knowledge comes into play.
### step1: create a .zok file to generate hash codes for the give password dataset.
### step2: we can create another .zok file or update this one itself to compare the input from user with the hash codes 
