#include <cryptopp/dsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <iostream>

using namespace CryptoPP;
using namespace std;

int main() {
    AutoSeededRandomPool rng;

    // Generate a 2048-bit DSA key pair
    DSA::PrivateKey privateKey;
    privateKey.GenerateRandomWithKeySize(rng, 2048);

    DSA::PublicKey publicKey;
    publicKey.AssignFrom(privateKey);

    // Save private key to DSA_Priv.bin
    FileSink privFile("DSA_Priv.bin");
    privateKey.DEREncode(privFile);
    privFile.MessageEnd();

    // Save public key to DSA_Pub.bin
    FileSink pubFile("DSA_Pub.bin");
    publicKey.DEREncode(pubFile);
    pubFile.MessageEnd();

    return 0;
}
