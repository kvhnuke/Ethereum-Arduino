/*
  RLP.cpp - RLP library for RLP functions
*/
#include "RLP.h"
using namespace std;

string RLP::encode(string s)
{
  	if(s.size()==1 && (int)s.at(0)<128)
  		return s;
	else{
		return encodeLength(s.size(), 128)+s;
	}
}
string RLP::encode(TX txobj)
{
  
}
string RLP::encodeLength(int len, int offset)
{
	string temp;
  	if(len<56){
  		temp=(char)(len+offset);
  		return temp;
  	}else{
  		string hexLength = intToHex(len);
		int	lLength =   hexLength.size()/2;
		string fByte = intToHex(offset+55+lLength);
		temp=fByte+hexLength;
		return temp;	
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

string RLP::string_to_hex(string input)
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

