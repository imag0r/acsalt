#include "pch.h"
#include "exception_strm.h"

#include "encoder.h"

std::wostream& operator<<(std::wostream& os, const std::exception& exc)
{
    try
    {
        os << encoder::to_wstring(exc.what());
    }
    catch (const std::exception&)
    {
    }

    return os;
}

std::ostream& operator<<(std::ostream& os, const std::exception& exc)
{
    os << exc.what();
    return os;
}
