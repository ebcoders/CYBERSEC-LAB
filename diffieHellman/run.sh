#!/bin/bash

# Ensure the script stops if any command fails
set -e

# Compile the C++ files
make
sleep 2
# Run the compiled binaries in the correct sequence
./1_setup 1024 160
./2_generate_alice_private_key
./3_generate_alice_public_key
./4_generate_bob_private_key
./5_generate_bob_public_key
./6_setupCA
./7_certificate_generation iit2022196@iiita.ac.in CA_Priv.bin publicKeyA.bin CertificateA.bin
./7_certificate_generation chagamkavya@gmail.com CA_Priv.bin publicKeyB.bin CertificateB.bin
./8_verify_certificate CertificateA.bin CA_Pub.bin
./8_verify_certificate CertificateB.bin CA_Pub.bin
./9_session_key_generation

sleep 2
# Verify that the session keys match
md5sum SSNKA.bin
md5sum SSNKB.bin
