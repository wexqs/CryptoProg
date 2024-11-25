#include <cryptopp/cryptlib.h>
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <iostream>
using namespace CryptoPP;
using namespace std;
int main()
{
    string hashMsg, msg;
    FileSource("/home/stud/CryptoProg/hash/test", true, new StringSink(msg));
    msg.resize(msg.size() - 1);
    cout << "Text from file: " << msg << endl;
    HexEncoder encoder(new FileSink(cout));
    Weak::MD5 hash;
    hash.Update((const byte*)&msg[0], msg.size());
    hashMsg.resize(hash.DigestSize());
    hash.Final((byte*)&hashMsg[0]);
    cout << "Text HASH: ";
    StringSource(hashMsg, true, new Redirector(encoder));
    cout <<"\n";
}
