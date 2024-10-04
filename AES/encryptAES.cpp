#include <iostream>
#include <fstream>
#include <string>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>

using namespace CryptoPP;

void encryptFile(const std::string& inputFile, const std::string& outputFile, 
                 const std::string& key, const std::string& iv) {
    try {
        std::ifstream in(inputFile, std::ios::binary);
        std::ofstream out(outputFile, std::ios::binary);

        SecByteBlock keyBytes((const byte*)key.data(), key.size());
        SecByteBlock ivBytes((const byte*)iv.data(), iv.size());

        CBC_Mode<AES>::Encryption encryptor;
        encryptor.SetKeyWithIV(keyBytes, keyBytes.size(), ivBytes);

        FileSource(in, true,
            new StreamTransformationFilter(encryptor,
                new FileSink(out)
            )
        );
    }
    catch(const Exception& e) {
        std::cerr << e.what() << std::endl;
    }
}


int main() {
    std::string inputFile, outputFile, key, iv;

    std::cout << "Encryption Program\n";
    std::cout << "Enter input JPEG file name: ";
    std::cin >> inputFile;
    std::cout << "Enter output encrypted file name: ";
    std::cin >> outputFile;
    outputFile += ".enc";
    std::cout << "Enter 16-byte key (32 hex characters): ";
    std::cin >> key;
    std::cout << "Enter 16-byte IV (32 hex characters): ";
    std::cin >> iv;

    try {
        std::string decodedKey, decodedIV;
        CryptoPP::HexDecoder decoder;
        decoder.Attach(new CryptoPP::StringSink(decodedKey));
        decoder.Put((byte*)key.data(), key.size());
        decoder.MessageEnd();

        decoder.Attach(new CryptoPP::StringSink(decodedIV));
        decoder.Put((byte*)iv.data(), iv.size());
        decoder.MessageEnd();

        if (decodedKey.length() != 16 || decodedIV.length() != 16) {
            throw std::runtime_error("Invalid key or IV length");
        }

        encryptFile(inputFile, outputFile, decodedKey, decodedIV);
        std::cout << "Encryption completed successfully.\n";
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}