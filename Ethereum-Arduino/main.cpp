#include <iostream>
#include "RLP.h"
#include <string>
#include "keccak.h"
#include <memory.h>
extern "C" {
#include "ecdsa.h"
#include "bignum256.h"
}
uint8_t* charArrtoUint(char src[]){
    uint8_t dest[sizeof(src)];
    for(int i=0;i<sizeof(src);i++){
        dest[i] = (int)src[i];
    }
    return dest;
}
char* uintToCharArr(uint8_t src[], int len){
    char dest[len];
    for(int i=0;i<len;i++){
        dest[i] = src[i];
    }
    return dest;
}
void splitArray(uint8_t src[], uint8_t dest[], uint8_t from, uint8_t to)
{
    int i = 0;
	for(int ctr=from; ctr<to; ctr++)
	{
		dest[i]	=  src[ctr];
		i++;
	}
}
int main(int argc, char** argv) {
    using namespace std;
	RLP rlp;
	TX tx;
    tx.nonce="0xFF";
    tx.gasPrice="0x09184e72a000";
    tx.gasLimit="0x2710";
    tx.to="0x0000000000000000000000000000000000000000";
    tx.value="0x00";
    tx.data="0x7f7465737432000000000000000000000000000000000000000000000000000000600057";
    tx.v="";
    tx.r="";
    tx.s="";
   // std::cout << rlp.bytesToHex(rlp.hexToRlpEncode("0x01")) << std::endl;
    string privkey = "e331b6d69882b4cb4ea581d88e0b604039a3de5967688d3dcffdd2270c0fd109";
    char inp [privkey.length()] = {};
	memcpy(inp,privkey.c_str(),privkey.length());
    char dest [sizeof(inp)/2] = {};
	rlp.hex2bin(inp,dest);
	 //std::cout << rlp.bytesToHex(string(dest,sizeof(dest))) << std::endl;
    uint8_t privatekey[32] = {227, 49, 182, 214, 152, 130, 180, 203, 78, 165, 129, 216, 142, 11, 96, 64, 57, 163, 222, 89, 103, 104, 141, 61, 207, 253, 210, 39, 12, 15, 209, 9};
   // uint8_t privatekey[32] = {9, 209, 15, 12, 39, 210, 253, 207, 61, 141, 104, 103, 89, 222, 163, 57, 64, 96, 11, 142, 216, 129, 165, 78, 203, 180, 130, 152, 214, 182, 49, 227};
   // uint8_t privatekey[32] = {9, 209, 15, 12, 39, 210, 253, 207, 61, 141, 104, 103, 89, 222, 163, 57, 64, 96, 11, 142, 216, 129, 165, 78, 203, 180, 130, 152, 214, 182, 49, 227};
    //uint8_t kval[32] = {197, 78, 238, 100, 243, 130, 96, 226, 175, 137, 148, 101, 57, 228, 37, 26, 116, 153, 136, 188, 166, 214, 191, 222, 104, 105, 178, 65, 19, 159, 143, 152};
    //privatekey[0] = (uint8_t)atoi(dest);
   // charArrtoUint(dest,privatekey);
    uint8_t hashval[32] = {200, 215, 201, 225, 52, 171, 175, 175, 142, 42, 131, 206, 158, 34, 122, 14, 203, 193, 134, 242, 88, 247, 143, 196, 28, 14, 93, 150, 35, 218, 22, 86};
  //  uint8_t hashval[32] = {86, 22, 218, 35, 150, 93, 14, 28, 196, 143, 247, 88, 242, 134, 193, 203, 14, 122, 34, 158, 206, 131, 42, 142, 175, 175, 171, 52, 225, 201, 215, 200};
    //uint8_t hashval[32] = {86, 22, 218, 35, 150, 93, 14, 28, 196, 143, 247, 88, 242, 134, 193, 203, 14, 122, 34, 158, 206, 131, 42, 142, 175, 175, 171, 52, 225, 201, 215, 200};
    uint8_t sig[64] = {0};
    uint8_t recid[1] = {0};
    //uECC_sign(privatekey, hashval, sizeof(hashval), kval, sig, uECC_secp256k1(), recid);
   // uint8_t v = recid[0]==1 ? 28:27;
   // cout<<rlp.intToHex(v)<<endl;
    uint8_t r[32];
    uint8_t s[64];
    //ecdsaSign2(5);
    //ecdsaSign(r,s,r,s);
    ecdsaSign((BigNum256)r, (BigNum256)s, (BigNum256)hashval, (BigNum256)privatekey);
   // cout << rlp.bytesToHex(string(uintToCharArr(s,32),32)) << "\n";
    //splitArray(sig,r,0,32);
   // splitArray(sig,s,32,64);
    tx.v = "0x1b";//+rlp.intToHex(v);
    tx.r = "0x"+rlp.bytesToHex(string(uintToCharArr(r,32),32));
    tx.s = "0x"+rlp.bytesToHex(string(uintToCharArr(s,32),32));
    //string temp = string(sig,sizeof(sig));
    //cout<<tx.v<<" "<<tx.r<<" "<<tx.s<<"\n" ;
   //cout<<rlp.bytesToHex(rlp.encode(tx,false));
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




