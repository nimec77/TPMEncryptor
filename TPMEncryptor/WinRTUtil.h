#pragma once

#include <vector>
#include <winrt/Windows.Storage.Streams.h>

namespace WinRTUtil
{
    std::vector<uint8_t> IBufferToVector(const winrt::Windows::Storage::Streams::IBuffer& buffer);
}
