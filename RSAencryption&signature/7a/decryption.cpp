#include <iostream>
#include <fstream>
#include <cryptopp/integer.h>
#include <cryptopp/nbtheory.h>
#include <cryptopp/osrng.h>

using namespace CryptoPP;
using namespace std;

// Function to load an Integer from a binary file
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

// RSA Decryption Phase
Integer decrypt(const Integer& c, const Integer& d, const Integer& n) {
    cout << "Decryption done\n";
    return a_exp_b_mod_c(c, d, n);
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        cout << "Usage: " << argv[0] << " <private key file> <public key n file> <ciphertext file>" << endl;
        return 1;
    }
    try {
        // Load private key and modulus
        Integer d = loadIntegerFromFile(argv[1]);
        Integer n = loadIntegerFromFile(argv[2]);

        // Load the ciphertext from a file
        Integer c = loadIntegerFromFile(argv[3]);

        // Decryption Phase
        Integer decrypted = decrypt(c, d, n);

        // Convert decrypted Integer back to string
        string decryptedText((size_t)decrypted.MinEncodedSize(), 0x00);
        decrypted.Encode((CryptoPP::byte*)&decryptedText[0], decryptedText.size());

        // Print the decrypted text
        cout << "Decrypted text: " << decryptedText << endl;

    } catch (const exception& ex) {
        cerr << "Exception: " << ex.what() << endl;
        return 1;
    }
    return 0;
}