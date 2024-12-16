
// TPMEncryptorDlg.cpp : implementation file
//

#include "pch.h"
#include "framework.h"
#include "TPMEncryptor.h"
#include "TPMEncryptorDlg.h"
#include "afxdialogex.h"
#include <exception>
#include <string>
#include <atlstr.h>
#include <iostream>
#include <winrt/Windows.Foundation.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CTPMEncryptorDlg dialog

CTPMEncryptorDlg::CTPMEncryptorDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_TPMENCRYPTOR_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CTPMEncryptorDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CTPMEncryptorDlg, CDialogEx)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_ENCRYTP_BUTTON, &CTPMEncryptorDlg::OnBnClickedEncrytpButton)
	ON_BN_CLICKED(IDC_DECRYTP_BUTTON, &CTPMEncryptorDlg::OnBnClickedDecrytpButton)
	ON_BN_CLICKED(IDC_DELETE_KEY, &CTPMEncryptorDlg::OnBnClickedDeleteKey)
	ON_BN_CLICKED(IDC_SECURE_AUTH, &CTPMEncryptorDlg::OnBnClickedSecureDescr)
	ON_BN_CLICKED(IDC_CHECK_TPM, &CTPMEncryptorDlg::OnBnClickedCheckTpm)
END_MESSAGE_MAP()


// CTPMEncryptorDlg message handlers

BOOL CTPMEncryptorDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

	// TODO: Add extra initialization here
	winrt::init_apartment(); // Initialize the Windows Runtime

	return TRUE;  // return TRUE  unless you set the focus to a control
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CTPMEncryptorDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

// The system calls this function to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CTPMEncryptorDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

void CTPMEncryptorDlg::OnBnClickedEncrytpButton()
{
	CString plainText;
	GetDlgItemText(IDC_PLAIN_TEXT_EDIT, plainText);

	try {
		CT2CA pszConvertedAnsiString(plainText);
		auto pSid = m_secureDescrService.GetCurrentUserSid();
		auto secureDescrData = m_secureDescrService.CreateSecureDescriptor(pSid);
		std::string convertedString(pszConvertedAnsiString);
		std::string encrypted = m_encryptor.Encrypt(convertedString, secureDescrData);
		std::string base64Encoded = TMPEncryptorHelper::Base64Encode(encrypted);
		CString cstr(base64Encoded.c_str());
		SetDlgItemText(IDC_ENCRYTPED_TEXT, cstr);
		MessageBox(L"Encrypted!");
	}
	catch (const std::exception& e) {
		MessageBox(CString(e.what()));
	}
}


void CTPMEncryptorDlg::OnBnClickedDecrytpButton()
{
	CString chipherText;
	GetDlgItemText(IDC_ENCRYTPED_TEXT, chipherText);

	try {
		CT2CA pszConvertedAnsiString(chipherText);
		std::string convertedString(pszConvertedAnsiString);
		std::string base64Decoded = TMPEncryptorHelper::Base64Decode(convertedString);
		std::string decrypted = m_encryptor.Decrypt(base64Decoded);
		CString cstr(decrypted.c_str());
		MessageBox(L"Decrypted: " + cstr);
	}
	catch (const std::exception& e) {
		MessageBox(CString(e.what()));
	}
}


void CTPMEncryptorDlg::OnBnClickedDeleteKey()
{
	try {
		m_encryptor.DeleteKey();
		MessageBox(L"Key deleted");
	}
	catch (const std::exception& e) {
		MessageBox(CString(e.what()));
	}
}


void CTPMEncryptorDlg::OnBnClickedSecureDescr()
{
	try {
		auto isAuth = m_userAuth.AuthenticateAsync().get();
		if (isAuth) {
			MessageBox(L"Authenticated!");
		}
		else {
			MessageBox(L"Authentication failed!");
		}
	}
	catch (const std::exception& e) {
		MessageBox(CString(e.what()));
	}
}


void CTPMEncryptorDlg::OnBnClickedCheckTpm()
{

	try {
		auto tpmVersion = m_encryptor.isWindowsTPMSupported();
		CString cstr;
		cstr.Format(L"TPM Version: %d", tpmVersion);
		MessageBox(cstr);
	}
	catch (const std::exception& e) {
		MessageBox(CString(e.what()));
	}
}