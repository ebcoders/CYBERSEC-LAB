#include <cryptopp/sha.h>
#include <cryptopp/dsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <cryptopp/base64.h>
#include <cryptopp/filters.h>
#include <iostream>
#include <string>

using namespace CryptoPP;
using namespace std;

int main() {
    AutoSeededRandomPool rng;

    try {
        // Load CA's DSA public key
        DSA::PublicKey dsaPublicKey;
        FileSource pubFile("DSA_Pub.bin", true);
        dsaPublicKey.BERDecode(pubFile);

        // Load the certificate
        string certificateData;
        FileSource certFile("certificate.bin", true, new StringSink(certificateData));

        // Print the loaded certificate data
        cout << "Certificate Data (Before Signature Extraction):" << endl;
        cout << certificateData << endl;

        // Extract signature from the certificate
        size_t pos = certificateData.find("Signature: ");
        if (pos == string::npos) {
            cerr << "Error: Signature not found in the certificate data!" << endl;
            return -1;
        }

        // Extract signature and certificate data
        string signature = certificateData.substr(pos + 10);  // Extract signature
        certificateData = certificateData.substr(0, pos);  // Extract certificate data without signature

        // Print the extracted signature
        cout << "Extracted Signature:" << endl;
        cout << signature << endl;

        // Decode the signature from Base64
        string decodedSignature;
        StringSource(signature, true, new Base64Decoder(new StringSink(decodedSignature)));

        // Print the decoded signature
        cout << "Decoded Signature:" << endl;
        for (unsigned char c : decodedSignature) {
            printf("%02x", c);
        }
        cout << endl;

        // Generate hash of the certificate data
        SHA256 hash;
        string digest;
        StringSource ss(certificateData, true, new HashFilter(hash, new StringSink(digest)));

        // Verify the signature using DSA
        DSA::Verifier dsaVerifier(dsaPublicKey);
        bool result = false;

        // Create a StringSource with the digest and decoded signature for verification
        // The correct order is: "digest + decodedSignature"
        string toVerify = digest + decodedSignature;
        StringSource ss2(toVerify, true,
            new SignatureVerificationFilter(dsaVerifier, new ArraySink((CryptoPP::byte*)&result, sizeof(result)), SignatureVerificationFilter::PUT_RESULT));

        // Print the verification result
        if (result) {
            cout << "Certificate verification successful!" << endl;
        } else {
            cout << "Certificate verification failed!" << endl;
        }
    } catch (const Exception& e) {
        cerr << "Error: " << e.what() << endl;
        return -1;
    }

    return 0;
}
