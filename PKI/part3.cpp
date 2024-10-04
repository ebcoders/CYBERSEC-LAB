#include <cryptopp/sha.h>
#include <cryptopp/dsa.h>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <cryptopp/base64.h>
#include <iostream>
#include <string>

using namespace CryptoPP;
using namespace std;

int main(int argc, char* argv[]) {
    if (argc != 2) {
        cerr << "Usage: " << argv[0] << " <user_email>" << endl;
        return -1;
    }

    string userEmail = argv[1];
    string certificateData = "Issuer: IIITA\nSubject ID: " + userEmail + "\nValidity:\nNotBefore: Sun, 16 Jun 2024\nNotAfter: Sun, 22 Jun 2026\n";

    AutoSeededRandomPool rng;

    try {
        // Load CA's DSA private key
        DSA::PrivateKey dsaPrivateKey;
        FileSource privFile("DSA_Priv.bin", true);
        dsaPrivateKey.BERDecode(privFile);

        // Load User's public key (RSA)
        RSA::PublicKey userPublicKey;
        FileSource pubFile("User_Pub.bin", true);
        userPublicKey.BERDecode(pubFile);

        // Generate hash of certificate data
        SHA256 hash;
        string digest;
        StringSource ss(certificateData, true, new HashFilter(hash, new StringSink(digest)));

        // Sign the hash using DSA (CA's private key)
        DSA::Signer dsaSigner(dsaPrivateKey);
        string signature;
        StringSource ss2(digest, true, new SignerFilter(rng, dsaSigner, new StringSink(signature)));

        // Encode the signature in Base64
        string encodedSignature;
        StringSource ss3(signature, true, new Base64Encoder(new StringSink(encodedSignature)));

        // Append signature to the certificate data
        certificateData += "Signature: " + encodedSignature + "\n";

        // Save the certificate to certificate.bin
        FileSink certFile("certificate.bin");
        certFile.Put(reinterpret_cast<const CryptoPP::byte*>(certificateData.data()), certificateData.size());
        certFile.MessageEnd();
    } catch (const Exception& e) {
        cerr << "Error: " << e.what() << endl;
        return -1;
    }

    return 0;
}
