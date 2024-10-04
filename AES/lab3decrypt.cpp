#include <iostream>
#include <fstream>
#include <string>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>

using namespace CryptoPP;
using namespace std;

int main() {
    string inputFilename, outputFilename, key, iv;
    
    cout << "Enter encrypted image filename: ";
    cin >> inputFilename;

    cout << "Enter output filename for decrypted image: ";
    cin >> outputFilename;

    cout << "Enter 16-byte key (in hexadecimal): ";
    cin >> key;
    if (key.length() != 32) {
        cerr << "Error: Key must be 16 bytes (32 hexadecimal characters)." << endl;
        return 1;
    }

    cout << "Enter 16-byte IV (in hexadecimal): ";
    cin >> iv;
    if (iv.length() != 32) { 
        cerr << "Error: IV must be 16 bytes (32 hexadecimal characters)." << endl;
        return 1;
    }

    SecByteBlock key_bytes(AES::MAX_KEYLENGTH);
    SecByteBlock iv_bytes(AES::BLOCKSIZE);
    StringSource(key, true, new HexDecoder(new ArraySink(key_bytes, key_bytes.size())));
    StringSource(iv, true, new HexDecoder(new ArraySink(iv_bytes, iv_bytes.size())));

   
    try {
        CBC_Mode<AES>::Decryption decryptor;
        decryptor.SetKeyWithIV(key_bytes, key_bytes.size(), iv_bytes);

        FileSource(inputFilename.c_str(), true,
            new StreamTransformationFilter(decryptor,
                new FileSink(outputFilename.c_str())
            )
        );

        cout << "Decryption complete. Decrypted file saved as: " << outputFilename << endl;
        cout << "Please verify that the decrypted image matches the original." << endl;
    }
    catch(const Exception& e) {
        cerr << "Decryption error: " << e.what() << endl;
        return 1;
    }

    return 0;
}