#pragma once

#include <windows.h>
#include <memory>
#include <bcrypt.h>
#include <ncrypt.h>
#include <winrt/windows.foundation.h>
#include <winrt/base.h>


namespace TPMEncryptor
{
	template<typename T>
	struct IInspectableWrapper : winrt::implements<IInspectableWrapper<T>, winrt::Windows::Foundation::IInspectable>
	{
		IInspectableWrapper(T state) : m_state(state) {}

		static winrt::Windows::Foundation::IInspectable box(T state)
		{
			return winrt::make<IInspectableWrapper>(state);
		}

		static T unbox(const winrt::Windows::Foundation::IInspectable& inspectable)
		{
			return winrt::get_self<IInspectableWrapper>(inspectable)->m_state;
		}

	private:
		T m_state;
	};

	struct BCryptKeyHandleDeleteTraits
	{
		using type = BCRYPT_KEY_HANDLE;

		static void close(type handle) noexcept
		{
			if (handle != nullptr) {
				BCryptDestroyKey(handle);
			}
		}

		static constexpr type invalid() noexcept
		{
			return nullptr;
		}
	};

	using BCryptDeleteKeyHandle = winrt::handle_type<BCryptKeyHandleDeleteTraits>;


	struct NCryptHandleFreeTraits
	{
		using type = NCRYPT_HANDLE;

		static void close(type handle) noexcept
		{
			if (handle != NULL) {
				NCryptFreeObject(handle);
			}
		}
		static constexpr type invalid() noexcept
		{
			return NULL;
		}
	};

	using NCryptHandleFree = winrt::handle_type<NCryptHandleFreeTraits>;

	struct MemoryDeallocation
	{
		void operator()(void* pBuffer) const
		{
			if (pBuffer != NULL)
			{
				LocalFree(reinterpret_cast<HLOCAL>(pBuffer));
			}
		}
	};

	struct NCryptHandleDeleter
	{
		void operator()(void* handle) const
		{
			if (handle != NULL)
			{
				NCryptFreeObject(reinterpret_cast<NCRYPT_HANDLE>(handle));
			}
		}
	};

	struct BCryptHandleDeleter
	{
		void operator()(BCRYPT_ALG_HANDLE handle) const
		{
			if (handle != NULL)
			{
				BCryptCloseAlgorithmProvider(handle, 0);
			}
		}
	};
	struct BCryptKeyHandleDeleter
	{
		void operator()(BCRYPT_KEY_HANDLE handle) const
		{
			if (handle != NULL)
			{
				BCryptDestroyKey(handle);
			}
		}
	};

	// Custom deleter for NCRYPT_KEY_HANDLE
	struct TokenHandleDeleter
	{
		void operator()(void* handle) const
		{
			if (handle != NULL)
			{
				CloseHandle(reinterpret_cast<HANDLE>(handle));
			}
		}
	};
}
