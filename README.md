# zero-knowledge-hackathon
creating a zero knowledge proof using zokrates
given below are the steps to create proofs to verify someones age eligibilty
here we have made two provers to prove the age comndition specified by the verifier.
the first one (eligibility_prover) proves if the codition is True and generates the proof json file.

And the second one (noneligible_prover) proves the condition wrong by reversing the condition in the .zok file and generates proof for the same.
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
#### zokrates compile -i gen_hash_for_password.zok
#### zokrates compute-witness -a 0 0 0 7
### the  hash codes would look like this
#### ~out_1 160635334427203623512968684759912538624
#### ~out_0 62133134181886812829768166950054220896

### step2: we can create another .zok file or update this one itself to compare the input from user with the hash codes 
#### zokrates compile -i gen_hash_for_password.zok
#### zokrates setup
#### zokrates export-verifier
#### zokrates compute-witness -a 0 0 0 7
#### zokrates generate-proof 
### now this proof authenticates that the password entered by the user is correct.

