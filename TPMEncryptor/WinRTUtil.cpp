#include "pch.h"
#include "WinRTUtil.h"

#include <winrt/windows.storage.streams.h>

using namespace winrt;
using namespace Windows::Storage::Streams;

inline std::vector<uint8_t> WinRTUtil::IBufferToVector(winrt::Windows::Storage::Streams::IBuffer buffer)
{
    std::vector<uint8_t> vec(buffer.Length());
    auto reader = DataReader::FromBuffer(buffer);
    reader.ReadBytes(winrt::array_view<uint8_t>(vec));

    return vec;
}
