#ifndef CONFIG_H_
#define CONFIG_H_

#include <string>
#include <map>
#include <iostream>
#include <fstream>
#include <sstream>
#include <exception>
using namespace std;

class config_exception : public exception
{
public:
    config_exception(int err, const string& message) : errnum(err), message(message) { }
    const char * what() const throw() { return message.c_str(); }
    const int geterr() const throw() { return this->errnum; }
    virtual ~config_exception() throw() { }

private:
    string message;
    int errnum;
};

/*
* Generic configuration Class
*
*/
class config {
protected:
    string m_Delimiter;  //!< separator between key and value
    string m_Comment;    //!< separator between value and comments
    map<string, string> m_Contents;  //!< extracted keys and values

    typedef map<string, string>::iterator mapi;
    typedef map<string, string>::const_iterator mapci;

public:
    config(string filename, string delimiter = "=", string comment = "#");
    config();
    //!<Search for key and read value or optional default value, call as read<T>
    template<class T> T Read(const string& in_key) const;
    template<class T> T Read(const string& in_key, const T& in_value) const;
    template<class T> bool ReadInto(T& out_var, const string& in_key) const;
    template<class T>
    bool ReadInto(T& out_var, const string& in_key, const T& in_value) const;
    bool FileExist(string filename);
    void ReadFile(string filename, string delimiter = "=", string comment = "#");

    // Check whether key exists in configuration
    bool KeyExists(const string& in_key) const;

    // Modify keys and values
    template<class T> void Add(const string& in_key, const T& in_value);
    void Remove(const string& in_key);

    // Check or change configuration syntax
    string GetDelimiter() const { return m_Delimiter; }
    string GetComment() const { return m_Comment; }
    string SetDelimiter( const string& in_s )
    { string old = m_Delimiter;  m_Delimiter = in_s;  return old; }
    string SetComment( const string& in_s )
    { string old = m_Comment;  m_Comment =  in_s;  return old; }

    // Write or read configuration
    friend ostream& operator<<(ostream& os, const config& cf);
    friend istream& operator>>(istream& is, config& cf);

protected:
    template<class T> static string T_as_string(const T& t);
    template<class T> static T string_as_T(const string& s);
    static void Trim(string& inout_s);
};


/* static */
template<class T>
string config::T_as_string(const T& t)
{
    // Convert from a T to a string
    // Type T must support << operator
    ostringstream ost;
    ost << t;
    return ost.str();
}

/* static */
template<class T>  
T config::string_as_T(const string& s)
{
    // Convert from a string to a T
    // Type T must support >> operator
    T t;
    istringstream ist(s);
    ist >> t;
    return t;
}

/* static */
template<>  
inline string config::string_as_T<string>(const string& s)
{
    // Convert from a string to a string
    // In other words, do nothing
    return s;
}

/* static */
template<>
inline bool config::string_as_T<bool>(const string& s)
{
    // Convert from a string to a bool
    // Interpret "false", "F", "no", "n", "0" as false
    // Interpret "true", "T", "yes", "y", "1", "-1", or anything else as true
    bool b = true;
    string sup = s;
    for (string::iterator p = sup.begin(); p != sup.end(); ++p)
        *p = toupper(*p);  // make string all caps
    if (sup == string("FALSE") || sup == string("F") || 
        sup == string("NO") || sup == string("N") || 
        sup == string("0") || sup == string("NONE"))
        b = false;
    return b;
}

template<class T>
T config::Read(const string& key) const
{
    // Read the value corresponding to key
    mapci p = m_Contents.find(key);
    if (p == m_Contents.end()) throw config_exception(2, "Configurate key not found, key = " + key);
    return string_as_T<T>(p->second);
}

template<class T>
T config::Read(const string& key, const T& value) const
{
    // Return the value corresponding to key or given default value
    // if key is not found
    mapci p = m_Contents.find(key);
    if (p == m_Contents.end()) return value;
    return string_as_T<T>(p->second);
}

template<class T>
bool config::ReadInto( T& var, const string& key ) const
{
    // Get the value corresponding to key and store in var
    // Return true if key is found
    // Otherwise leave var untouched
    mapci p = m_Contents.find(key);
    bool found = (p != m_Contents.end());
    if (found) var = string_as_T<T>(p->second);
    return found;
}

template<class T>
bool config::ReadInto(T& var, const string& key, const T& value) const
{
    // Get the value corresponding to key and store in var
    // Return true if key is found
    // Otherwise set var to given default
    mapci p = m_Contents.find(key);
    bool found = (p != m_Contents.end());
    if (found)
        var = string_as_T<T>(p->second);
    else
        var = value;
    return found;
}

template<class T>
void config::Add(const string& in_key, const T& value)
{
    // Add a key with given value
    string v = T_as_string(value);
    string key = in_key;
    Trim(key);
    Trim(v);
    m_Contents[key] = v;
}

#endif