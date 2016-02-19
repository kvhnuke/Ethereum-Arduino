/*
  RLP.cpp - RLP library for RLP functions
*/
#include "RLP.h"
using namespace std;

string RLP::encode(string s)
{
  	if(s.size()==1 && (unsigned char)s[0]<128)
  		return s;
	else{
		return encodeLength(s.size(), 128)+s;
	}
}
string RLP::encode(TX tx, bool toSign)
{
    string serialized = hexToRlpEncode(tx.nonce)+
                        hexToRlpEncode(tx.gasPrice)+
                        hexToRlpEncode(tx.gasLimit)+
                        hexToRlpEncode(tx.to)+
                        hexToRlpEncode(tx.value)+
                        hexToRlpEncode(tx.data);
    if(!toSign)
          serialized += hexToRlpEncode(tx.v)+
                        hexToRlpEncode(tx.r)+
                        hexToRlpEncode(tx.s);

    return hexToBytes(encodeLength(serialized.length(),192))+serialized;
}
string RLP::hexToBytes(string s){
    char inp [s.length()] = {};
	memcpy(inp,s.c_str(),s.length());
    char dest [sizeof(inp)/2] = {};
	hex2bin(inp,dest);
	return string(dest,sizeof(dest));
}
string RLP::hexToRlpEncode(string s){
    s = removeHexFormatting(s);
	return encode(hexToBytes(s));
}
string RLP::removeHexFormatting(string s){
    if(s[0]=='0'&&s[1]=='x')
        return s.substr(2,s.length()-2);
    return s;
}
string RLP::encodeLength(int len, int offset)
{
	string temp;
  	if(len<56){
  		temp=(char)(len+offset);
  		return temp;
  	}else{
  		string hexLength = intToHex(len);
		int	lLength =   hexLength.length()/2;
		string fByte = intToHex(offset+55+lLength);
		return fByte+hexLength;
	}
}
string RLP::intToHex(int n){
	stringstream stream;
	stream << std::hex << n;
	string result( stream.str() );
	if(result.size() % 2)
		result = "0"+result;
	return result;
}
string RLP::bytesToHex(string input)
{
    static const char* const lut = "0123456789ABCDEF";
    size_t len = input.length();
    std::string output;
    output.reserve(2 * len);
    for (size_t i = 0; i < len; ++i)
    {
        const unsigned char c = input[i];
        output.push_back(lut[c >> 4]);
        output.push_back(lut[c & 15]);
    }
    return output;
}
int RLP::char2int(char input)
{
  if(input >= '0' && input <= '9')
    return input - '0';
  if(input >= 'A' && input <= 'F')
    return input - 'A' + 10;
  if(input >= 'a' && input <= 'f')
    return input - 'a' + 10;
}
void RLP::hex2bin(const char* src, char* target)
{
  while(*src && src[1])
  {
    *(target++) = char2int(*src)*16 + char2int(src[1]);
    src += 2;
  }
}


