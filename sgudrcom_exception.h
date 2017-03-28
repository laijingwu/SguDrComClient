#ifndef SGUDRCOM_EXCEPTION_H_
#define SGUDRCOM_EXCEPTION_H_

#include <iostream>
#include <sstream>
#include <string.h>
#include <exception>
using namespace std;

class sgudrcom_exception : public exception
{
public:
	sgudrcom_exception(const string& message) : message(message) { }
	sgudrcom_exception(const string& message, int err) { // system error
        stringstream stream;
        stream << message << ", errno = " << err << ", desc: " << strerror(err);
        this->message = stream.str();
    }
	const char * what() const throw() { return message.c_str(); }
    virtual ~sgudrcom_exception() throw() { }

private:
	string message;
};

#endif