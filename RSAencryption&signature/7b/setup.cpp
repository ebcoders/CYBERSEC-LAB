#include <iostream>
#include <fstream>
#include <cryptopp/integer.h>
#include <cryptopp/osrng.h>
#include <cryptopp/nbtheory.h>

using namespace CryptoPP;
using namespace std;

// Function to generate a large prime number
Integer generatePrime(int bitLength) {
    AutoSeededRandomPool rng;
    PrimeAndGenerator pg;
    pg.Generate(1, rng, bitLength, bitLength - 1);
    return pg.Prime();
}

// Function to perform modular inverse
Integer modInverse(const Integer& a, const Integer& n) {
    return a.InverseMod(n);
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

// RSA Setup Phase
void setupPhase(Integer& n, Integer& e, Integer& d) {
    Integer p = generatePrime(1024);
    Integer q = generatePrime(1024);
    while (p == q) {
        q = generatePrime(1024);
    }

    n = p * q;
    Integer phi_n = (p - 1) * (q - 1);

    AutoSeededRandomPool rng;
    do {
        d.Randomize(rng, 512);
    } while (Integer::Gcd(d, phi_n) != Integer::One());

    e = modInverse(d, phi_n);

    saveIntegerToFile("publickey.bin", e);
    saveIntegerToFile("publickey_n.bin", n);
    saveIntegerToFile("privatekey.bin", d);
}

int main() {
    Integer n, e, d;

    try {
        setupPhase(n, e, d);
    } catch (const exception& ex) {
        cerr << "Error: " << ex.what() << endl;
        return 1;
    }

    cout << "RSA keys generated and saved successfully." << endl;
    return 0;
}