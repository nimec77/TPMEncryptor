
// TPMEncryptorDlg.h : header file
//

#pragma once

#include "TMPEncryptorHelper.h"
#include "SecureDescrService.h"
#include "MemoryDeallocation.h"
#include "WinHello.h"

// CTPMEncryptorDlg dialog
class CTPMEncryptorDlg : public CDialogEx
{
// Construction
public:
	CTPMEncryptorDlg(CWnd* pParent = nullptr);	// standard constructor

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_TPMENCRYPTOR_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support


// Implementation
protected:
	HICON m_hIcon;

	// Generated message map functions
	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();	
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedEncrytpButton();
	afx_msg void OnBnClickedDecrytpButton();

private:
	TMPEncryptorHelper m_encryptor;
	SecureDescrService m_secureDescrService;
	WinHello m_winHello;
public:
	afx_msg void OnBnClickedDeleteKey();
	afx_msg void OnBnClickedSecureDescr();
	afx_msg void OnBnClickedCheckTpm();
	afx_msg void OnBnClickedCreateEcdh();
	afx_msg void OnBnClickedGetEcdh();
	afx_msg void OnBnClickedCreateCredential();
	afx_msg void OnBnClickedTpmCheck();
	afx_msg void OnBnClickedOpenCred();
	afx_msg void OnBnClickedCreateKey();
};
