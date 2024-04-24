#pragma once

std::wostream& operator<<(std::wostream& os, const std::exception& exc);

std::ostream& operator<<(std::ostream& os, const std::exception& exc);
