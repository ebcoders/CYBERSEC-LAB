#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1  // Enable the use of weak algorithms like MD5

#include <iostream>
#include <fstream>
#include <cryptopp/integer.h>
#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <cryptopp/md5.h>
#include <cryptopp/files.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>

using namespace CryptoPP;

std::string computeMD5Hash(const std::string& filename) {
    Weak::MD5 hash;
    std::string digest;

    // Read the file and compute the MD5 hash
    CryptoPP::FileSource file(filename.c_str(), true, new HashFilter(hash, new HexEncoder(new StringSink(digest))));

    return digest;
}
void generate_session_key(const std::string &private_key_file, const std::string &other_public_key_file, const std::string &session_key_file, const Integer &p) {
    Integer private_key, other_public_key, session_key;

    // Load private key
    std::ifstream priv_file(private_key_file, std::ios::binary);
    if (!priv_file) {
        std::cerr << "Error: Unable to open " << private_key_file << std::endl;
        return;
    }
    priv_file >> private_key;
    priv_file.close();

    // Load the other party's public key
    std::ifstream pub_file(other_public_key_file, std::ios::binary);
    if (!pub_file) {
        std::cerr << "Error: Unable to open " << other_public_key_file << std::endl;
        return;
    }
    pub_file >> other_public_key;
    pub_file.close();

    // Compute the session key: SSNK ≡ (OtherPublicKey)^PrivateKey mod p
    session_key = a_exp_b_mod_c(other_public_key, private_key, p);

    // Save the session key to a binary file
    std::ofstream sess_file(session_key_file, std::ios::binary);
    if (sess_file) {
        sess_file << session_key;
        sess_file.close();
        std::cout << "Session key saved to " << session_key_file << std::endl;
    } else {
        std::cerr << "Error: Unable to save session key to " << session_key_file << std::endl;
    }
}

int main() {
    Integer g, p, q;

    // Load the parameters (g, p, q) from params.bin
    std::ifstream params_file("params.bin", std::ios::binary);
    if (!params_file) {
        std::cerr << "Error: Unable to open params.bin file." << std::endl;
        return 1;
    }
    params_file >> g >> p >> q;
    params_file.close();

    // Generate session keys for both parties
    generate_session_key("privatekeyA.bin", "publicKeyB.bin", "SSNKA.bin", p);
    generate_session_key("privatekeyB.bin", "publicKeyA.bin", "SSNKB.bin", p);

    std::string hashA = computeMD5Hash("SSNKA.bin");
    std::string hashB = computeMD5Hash("SSNKB.bin");

    std::cout << "Hash A: " << hashA << std::endl;
    std::cout << "Hash B: " << hashB << std::endl;

    if (hashA != hashB) {
        std::cout << "Session Generation Failed!\n";
    }
    else {
        std::cout << "Session Generated Successfully\n";
    }
    
    return 0;
}

// g++ -std=c++17 -I/opt/homebrew/Cellar/cryptopp/8.9.0/include -L/opt/homebrew/Cellar/cryptopp/8.9.0/lib Lab_Codes/Lab_6/session_key_generation.cpp -lcryptopp -o session_key_generation
// ./session_key_generation
