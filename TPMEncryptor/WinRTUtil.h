#pragma once

#include <vector>
#include <winrt/windows.foundation.h>
#include <winrt/Windows.Storage.Streams.h>


class WinRTUtil
{
    inline std::vector<uint8_t> IBufferToVector(winrt::Windows::Storage::Streams::IBuffer buffer);
};

