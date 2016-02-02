#include <iostream>
#include "RLP.h"
#include <string>
#include "keccak.h"
#include <memory.h>
#include "uECC.h"
#include <stdlib.h>
using namespace std;
uint8_t* charArrtoUint(char src[]){
    uint8_t dest[sizeof(src)];
    for(int i=0;i<sizeof(src);i++){
        dest[i] = (int)src[i];
    }
    return dest;
}
char* uintToCharArr(uint8_t src[]){
    char dest[sizeof(src)];
    for(int i=0;i<sizeof(src);i++){
        dest[i] = src[i];
    }
    return dest;
}
int main(int argc, char** argv) {
	RLP rlp;
	TX tx;
    tx.nonce="0xFF";
    tx.gasPrice="0x09184e72a000";
    tx.gasLimit="0x2710";
    tx.to="0x0000000000000000000000000000000000000000";
    tx.value="0x00";
    tx.data="0x7f7465737432000000000000000000000000000000000000000000000000000000600057";
    tx.r="";
    tx.v="";
    tx.s="";
    //std::cout << rlp.bytesToHex(rlp.encode(tx, true)) << std::endl;
    string privkey = "e331b6d69882b4cb4ea581d88e0b604039a3de5967688d3dcffdd2270c0fd109";
    char inp [privkey.length()] = {};
	memcpy(inp,privkey.c_str(),privkey.length());
    char dest [sizeof(inp)/2] = {};
	rlp.hex2bin(inp,dest);
	 //std::cout << rlp.bytesToHex(string(dest,sizeof(dest))) << std::endl;
    uint8_t privatekey[32] = {227, 49, 182, 214, 152, 130, 180, 203, 78, 165, 129, 216, 142, 11, 96, 64, 57, 163, 222, 89, 103, 104, 141, 61, 207, 253, 210, 39, 12, 15, 209, 9};
    //privatekey[0] = (uint8_t)atoi(dest);
   // charArrtoUint(dest,privatekey);
    uint8_t hashval[32] = {200, 215, 201, 225, 52, 171, 175, 175, 142, 42, 131, 206, 158, 34, 122, 14, 203, 193, 134, 242, 88, 247, 143, 196, 28, 14, 93, 150, 35, 218, 22, 86};
    uint8_t sig[64] = {0};
    uECC_sign(privatekey, hashval, sizeof(hashval), sig, uECC_secp256k1());
    //string temp = string(sig,sizeof(sig));
    for(int i=0;i<64;i++){
        cout<<(int)sig[i]<< " ";;
    }
   // std::cout << rlp.bytesToHex(string(uintToCharArr(sig),64)) << std::endl;

	//cout << rlp.encodeLength(5, 60) << "\n";
	//cout << rlp.intToHex(5) << "\n";
	//string s = rlp.encode("\255");
	//s = rlp.string_to_hex(s);
	//cout << s << endl;
	//Keccak k;
	//std::cout << k("\0") << std::endl;
	//std::cout << rlp.string_to_hex(rlp.hexToRlpEncode(tx.nonce)) << std::endl;
	//out << rlp.string_to_hex(rlp.encode((string)dest)) << endl;
	//std::cout << (string)dest << std::endl;
}

