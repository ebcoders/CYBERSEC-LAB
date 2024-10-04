#include <iostream>
#include <fstream>
#include <string>
#include <cryptopp/integer.h>
#include <cryptopp/nbtheory.h>
#include <cryptopp/osrng.h>
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>

using namespace CryptoPP;
using namespace std;

// Function to save a hash to a binary file (remains unchanged)
void saveHashToFile(const string& hash, const string& filename) {
    ofstream file(filename, ios::binary);
    file.write(hash.c_str(), hash.size());
    file.close();
}

// Function to load an Integer from a binary file (remains unchanged)
Integer loadIntegerFromFile(const string& filename) {
    ifstream file(filename, ios::binary | ios::ate);
    if (!file) {
        throw runtime_error("Cannot open file: " + filename);
    }

    streamsize size = file.tellg();
    file.seekg(0, ios::beg);
    CryptoPP::byte* buffer = new CryptoPP::byte[size];
    if (!file.read((char*)buffer, size)) {
        delete[] buffer;
        throw runtime_error("Failed to read from file: " + filename);
    }

    Integer integer;
    integer.Decode(buffer, size);
    delete[] buffer;
    return integer;
}

// RSA Verification Phase
bool verifySignature(const Integer& hash, const Integer& signature, const Integer& e, const Integer& n) {
    Integer hash_prime = a_exp_b_mod_c(signature, e, n);
    return hash == hash_prime;
}

int main(int argc, char* argv[]) {
    if (argc < 5) {
        cout << "Usage: " << argv[0] << " <public key file> <public key n file> <hash file> <signature file>" << endl;
        return 1;
    }

    try {
        Integer e = loadIntegerFromFile(argv[1]);
        Integer n = loadIntegerFromFile(argv[2]);

        // Load the hash from the file instead of generating it from message
        Integer hash = loadIntegerFromFile(argv[3]);

        Integer signature = loadIntegerFromFile(argv[4]);

        bool isValid = verifySignature(hash, signature, e, n);
        cout << (isValid ? "Signature is valid." : "Signature is invalid.") << endl;

    } catch (const exception& ex) {
        cerr << "Exception: " << ex.what() << endl;
        return 1;
    }

    return 0;
}