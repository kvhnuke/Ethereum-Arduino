/*
  RLP.h - RLP library for RLP functions
*/
#ifndef RLP_h
#define RLP_h
#include <stdio.h>
#include<string>
#include<iomanip>
#include <sstream>
#include "TX.h"
class RLP
{
  public:
    std::string encode(std::string);
    std::string encode(TX);
  	std::string encodeLength(int, int);
  	std::string intToHex(int);
  	std::string string_to_hex(std::string);
  private:

};

#endif


