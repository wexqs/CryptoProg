#include <iostream>
#include <string>
#include <fstream>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include "cryptopp/cryptlib.h"
#include "cryptopp/pwdbased.h"
#include "cryptopp/sha.h"
#include "cryptopp/hex.h"
#include <cryptopp/aes.h>
#include <cryptopp/files.h>
#include <cryptopp/rijndael.h>

using namespace CryptoPP;
using namespace std;

int main(int argc, char* argv[])
{
    //Пароль, Путь к файлу чтения, Путь к файлу записи, Режим работы
    string pass, input, output, ende;
    cout << "Введите режим en/de:" << endl;
    cin >> ende;

    if (ende == "en") {
        cout << "Создайте пароль:" << endl;
        cin >> pass;
        cout << "Укажите путь к файлу чтения:" << endl;
        cin >> input;
        cout << "Укажите путь к файлу записи:" << endl;
        cin >> output;

        byte bPass[pass.size()];
        StringSource(pass, true, new HexEncoder(new ArraySink(bPass, sizeof(bPass))));
        size_t plen = strlen((const char*)bPass);

        AutoSeededRandomPool GSALT;
        byte SALT[AES::BLOCKSIZE];
        GSALT.GenerateBlock(SALT, sizeof(SALT));
        size_t slen = strlen((const char*)SALT);

        byte key[SHA256::DIGESTSIZE];
        PKCS12_PBKDF<SHA256> bibl;
        byte purpose = 0;
        bibl.DeriveKey(key, sizeof(key), purpose, bPass, plen, SALT, slen, 1024, 0.0f);

        AutoSeededRandomPool GVI;
        byte IV[AES::BLOCKSIZE];
        GVI.GenerateBlock(IV, sizeof(IV));

        ofstream userPass("/home/stud/CryptoProg/cipher/userPass");
        StringSource(pass, true, new FileSink(userPass));

        ofstream userKey("/home/stud/CryptoProg/cipher/Key");
        ArraySource(key, sizeof(key), true, new FileSink(userKey));

        ofstream userIV("/home/stud/CryptoProg/cipher/fileIV");
        ArraySource(IV, sizeof(IV), true, new FileSink(userIV));

        CBC_Mode<AES>::Encryption ECBC;
        ECBC.SetKeyWithIV(key, sizeof(key), IV);

        ifstream inputf(input);
        if (!inputf) {
            cerr << "Не удалось открыть файл для чтения: " << input << endl;
            return 1;
        }

        ofstream outputf(output);
        FileSource(inputf, true, new StreamTransformationFilter(ECBC, new FileSink(outputf)));

        inputf.close();
        outputf.close();
    } else if (ende == "de") {
        string pass;
        cout << "Пароль:" << endl;
        string passNow;
        cin >> passNow;

        FileSource("/home/stud/CryptoProg/cipher/userPass", true, new StringSink(pass));

        if (pass != passNow) {
            cout << "Неправильный пароль\n";
            return 1;
        }

        cout << "Укажите путь к файлу чтения:" << endl;
        cin >> input;
        cout << "Укажите путь к файлу записи:" << endl;
        cin >> output;

        byte key[SHA256::DIGESTSIZE];
        FileSource("/home/stud/CryptoProg/cipher/Key", true, new ArraySink(key, sizeof(key)));

        byte IV[AES::BLOCKSIZE];
        FileSource("/home/stud/CryptoProg/cipher/fileIV", true, new ArraySink(IV, sizeof(IV)));

        CBC_Mode<AES>::Decryption DCBC;
        DCBC.SetKeyWithIV(key, sizeof(key), IV);

        ifstream inputf(input);
        if (!inputf) {
            cerr << "Не удалось открыть файл для чтения: " << input << endl;
            return 1;
        }

        ofstream outputf(output);
        FileSource(inputf, true, new StreamTransformationFilter(DCBC, new FileSink(outputf)));

        inputf.close();
        outputf.close();
    } else {
        cerr << "Ошибка: неправильный режим - " << ende << endl;
        exit(1);
    }
}
