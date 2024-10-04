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

// Function to generate an MD5 hash of a message
string generateMD5Hash(const string& message) {
    CryptoPP::byte digest[Weak::MD5::DIGESTSIZE];
    Weak::MD5 hash;
    hash.CalculateDigest(digest, (const CryptoPP::byte*)message.data(), message.size());
    return string((char*)digest, Weak::MD5::DIGESTSIZE);
}

// Function to save a hash to a binary file
void saveHashToFile(const string& hash, const string& filename) {
    ofstream file(filename, ios::binary);
    file.write(hash.c_str(), hash.size());
    file.close();
}

// RSA Signature Phase
Integer signMessage(const Integer& hash, const Integer& d, const Integer& n) {
    cout<<"Signature generated\n";
    return a_exp_b_mod_c(hash, d, n);
}

// Function to write an Integer to a binary file
void saveIntegerToFile(const string& filename, const Integer& integer) {
    ofstream file(filename, ios::binary);
    if (!file) {
        throw runtime_error("Cannot open file for writing: " + filename);
    }
    size_t size = integer.MinEncodedSize();
    CryptoPP::byte* buffer = new CryptoPP::byte[size];
    integer.Encode(buffer, size);
    file.write((char*)buffer, size);
    delete[] buffer;
}

// Function to read an Integer from a binary file
Integer loadIntegerFromFile(const string& filename) {
    ifstream file(filename, ios::binary | ios::ate);
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

// Function to convert binary data to a hexadecimal string
string toHexString(const CryptoPP::byte* digest, size_t size) {
    static const char* const lut = "0123456789ABCDEF";
    string result;
    result.reserve(2 * size);
    for (size_t i = 0; i < size; ++i) {
        const unsigned char c = digest[i];
        result.push_back(lut[c >> 4]);
        result.push_back(lut[c & 15]);
    }
    return result;
}


int main(int argc, char* argv[]) {
    if (argc < 4) {
        cout << "Usage: " << argv[0] << " <private key file> <public key n file> <message file>" << endl;
        return 1;
    }

    try {
        // Load the private key and modulus
        Integer d = loadIntegerFromFile(argv[1]);
        Integer n = loadIntegerFromFile(argv[2]);

        // Load the message from the file
        ifstream messageFile(argv[3]);
        if (!messageFile) {
            throw runtime_error("Failed to open message file.");
        }
        string message((istreambuf_iterator<char>(messageFile)), istreambuf_iterator<char>());
        messageFile.close();

        // Generate and save the MD5 hash of the message
        string hashString = generateMD5Hash(message);
        cout << "MD5 Hash of the message: " << toHexString(reinterpret_cast<const CryptoPP::byte*>(hashString.data()), hashString.size()) << endl;
        saveHashToFile(hashString, "msghash.bin");

        // Convert hash to Integer
        Integer hash((const CryptoPP::byte*)hashString.data(), hashString.size());

        // Sign the hash
        Integer signature = signMessage(hash, d, n);

        // Save the signature to "signature.bin"
        saveIntegerToFile("signature.bin", signature);

    } catch (const exception& ex) {
        cerr << "Exception: " << ex.what() << endl;
        return 1;
    }

    return 0;
}