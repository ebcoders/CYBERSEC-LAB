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

// Function to write an Integer to a binary file
void saveIntegerToFile(const string& filename, const Integer& integer) {
    ofstream file(filename, ios::binary);
    size_t size = integer.MinEncodedSize();
    CryptoPP::byte* buffer = new CryptoPP::byte[size];
    integer.Encode(buffer, size);
    file.write((char*)buffer, size);
    delete[] buffer;
    file.close();
}

// RSA Encryption Phase
Integer encrypt(const Integer& m, const Integer& e, const Integer& n) {
    cout << "Encryption done\n";
    return a_exp_b_mod_c(m, e, n);
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        cout << "Usage: " << argv[0] << " <public key file> <public key n file> <message file>" << endl;
        return 1;
    }
    try {
        // Load public key and modulus
        Integer e = loadIntegerFromFile(argv[1]);
        Integer n = loadIntegerFromFile(argv[2]);

        // Load the plaintext from a file
        ifstream plainFile(argv[3]);
        if (!plainFile) {
            throw runtime_error("Failed to open plaintext file.");
        }
        string plainText((istreambuf_iterator<char>(plainFile)), istreambuf_iterator<char>());
        plainFile.close();

        // Convert plaintext to Integer
        Integer m((const CryptoPP::byte*)plainText.data(), plainText.size());

        // Encryption Phase
        Integer c = encrypt(m, e, n);

        // Save the ciphertext
        saveIntegerToFile("ciphertext.bin", c);

    } catch (const exception& ex) {
        cerr << "Exception: " << ex.what() << endl;
        return 1;
    }
    return 0;
}