#ifndef SGUDRCOM_EXCEPTION_H_
#define SGUDRCOM_EXCEPTION_H_

#include <iostream>
#include <sstream>
#include <string.h>
using namespace std;

class sgudrcom_exception
{
public:
	sgudrcom_exception(const std::string& message) : message(message) { }
	sgudrcom_exception(const std::string& message, int err) {
        std::stringstream stream;
        stream << message << ", errno = " << err << ", desc: " << strerror(err);
        this->message = stream.str();
    }
	const char * get() const throw() { return message.c_str(); }
    ~sgudrcom_exception() throw() { }

private:
	std::string message;

};

#endif