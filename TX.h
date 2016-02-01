/*
  TX.h - Transaction library for TX functions
*/
#ifndef TX_h
#define TX_h
#include<string>
class TX
{
  public:
    std::string nonce;
    std::string gasPrice;
    std::string gasLimit;
    std::string to;
    std::string value;
    std::string data;
    std::string v;
    std::string r;
    std::string s;
  private:
};

#endif


