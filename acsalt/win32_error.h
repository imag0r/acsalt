#pragma once

class win32_error : public std::runtime_error
{
public:
    win32_error(const std::string& msg, unsigned last_error = ::GetLastError());

    unsigned last_error() const throw();

private:
    unsigned last_error_;

    static std::string get_message(unsigned last_error, const std::string& msg);
};
