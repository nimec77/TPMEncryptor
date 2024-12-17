#pragma once

#include <string>
#include <winrt/base.h>

class StringConverter
{
public:
	static std::string ConvertWideStringToString(const std::wstring& wideString);
	static std::wstring ConvertStringToWideString(const std::string& string);
	static std::string ConvertHStringToString(const winrt::hstring& hstring);
};

