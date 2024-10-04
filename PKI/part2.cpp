#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>

using namespace CryptoPP;

int main() {
    AutoSeededRandomPool rng;

    // Generate a 1024-bit RSA key pair
    RSA::PrivateKey privateKey;
    privateKey.GenerateRandomWithKeySize(rng, 1024);

    RSA::PublicKey publicKey(privateKey);

    // Save private key to User_Priv.bin
    FileSink privFile("User_Priv.bin");
    privateKey.DEREncode(privFile);
    privFile.MessageEnd();

    // Save public key to User_Pub.bin
    FileSink pubFile("User_Pub.bin");
    publicKey.DEREncode(pubFile);
    pubFile.MessageEnd();

    return 0;
}
