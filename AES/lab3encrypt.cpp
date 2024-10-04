#include <iostream>
#include <fstream>
#include <string>
#include <algorithm>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>

using namespace CryptoPP;
using namespace std;

bool isJPEG(const string& filename) {
    string ext = filename.substr(filename.find_last_of(".") + 1);
    transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
    return (ext == "jpg" || ext == "jpeg");
}

int main() {
    string inputFilename, outputFilename, key, iv;
    
    // Step 1: Accept inputs from the terminal
    cout << "Enter input image filename (JPEG format): ";
    cin >> inputFilename;
    if (!isJPEG(inputFilename)) {
        cerr << "Error: Input file must be a JPEG image." << endl;
        return 1;
    }

    cout << "Enter output filename for encrypted image: ";
    cin >> outputFilename;

    cout << "Enter 16-byte key (in hexadecimal): ";
    cin >> key;
    if (key.length() != 32) {  // 16 bytes in hex is 32 characters
        cerr << "Error: Key must be 16 bytes (32 hexadecimal characters)." << endl;
        return 1;
    }

    cout << "Enter 16-byte IV (in hexadecimal): ";
    cin >> iv;
    if (iv.length() != 32) {  // 16 bytes in hex is 32 characters
        cerr << "Error: IV must be 16 bytes (32 hexadecimal characters)." << endl;
        return 1;
    }

    // Convert key and IV from hex to byte array
    SecByteBlock key_bytes(AES::MAX_KEYLENGTH);
    SecByteBlock iv_bytes(AES::BLOCKSIZE);
    StringSource(key, true, new HexDecoder(new ArraySink(key_bytes, key_bytes.size())));
    StringSource(iv, true, new HexDecoder(new ArraySink(iv_bytes, iv_bytes.size())));

    // Step 2: Encrypt the image using AES
    try {
        CBC_Mode<AES>::Encryption encryptor;
        encryptor.SetKeyWithIV(key_bytes, key_bytes.size(), iv_bytes);

        FileSource(inputFilename.c_str(), true,
            new StreamTransformationFilter(encryptor,
                new FileSink(outputFilename.c_str())
            )
        );

        // Step 3: Save the encrypted image
        cout << "Encryption complete. Encrypted file saved as: " << outputFilename << endl;
    }
    catch(const Exception& e) {
        cerr << "Encryption error: " << e.what() << endl;
        return 1;
    }

    return 0;
}