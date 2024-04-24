#pragma once

template <class Type>
struct iless : public std::binary_function<Type, Type, bool>
{
    bool operator()(const Type& _Left, const Type& _Right) const
    {
        return boost::ilexicographical_compare<Type>(_Left, _Right);
    }
};
