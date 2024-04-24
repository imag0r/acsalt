#pragma once

#include <Windows.h>
#include <wincrypt.h>
#include <Shlwapi.h>

#pragma comment(lib, "crypt32")

#include <iostream>
#include <map>
#include <string>
#include <vector>

#pragma warning(push)
#pragma warning(disable: 4459)
#include "boost/algorithm/string.hpp"
#include "boost/interprocess/managed_windows_shared_memory.hpp"
#include "boost/interprocess/sync/named_mutex.hpp"
#include "boost/json.hpp"
#include "boost/noncopyable.hpp"
#include "boost/thread.hpp"
#pragma warning(pop)
