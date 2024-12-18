#pragma once

#include <winrt/base.h>

using namespace winrt;

namespace winrt::impl
{
	inline constexpr hresult error_user_prefers_password{ static_cast<hresult>(0xA0081001) };
	inline constexpr hresult error_secure_device_locked{ static_cast<hresult>(0x8007139F) };
}
