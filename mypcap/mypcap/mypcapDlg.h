
// mypcapDlg.h : 头文件
//

#pragma once
#include "afxcmn.h"
#include "afxwin.h"
#include"pcap.h"

// CmypcapDlg 对话框
class CmypcapDlg : public CDialogEx
{
// 构造
public:
	CmypcapDlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
	enum { IDD = IDD_MYPCAP_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
    CListCtrl m_listCtrl;
	CComboBox m_comboBox;
	CComboBox m_comboBoxRule;
	CTreeCtrl m_treeCtrl;
	CEdit m_edit;
	CButton m_buttonStart;
	CButton m_buttonStop;
	CButton m_buttonSave;
	CButton m_buttonRead;
	CEdit m_editNTcp;
	CEdit m_editNUdp;
	CEdit m_editNIcmp;
	CEdit m_editNHttp;
	CEdit m_editNArp;
	CEdit m_editIcmpv6;
	CEdit m_editNIpv6;
	CEdit m_editNIpv4;
	CEdit m_editNOther;
	CEdit m_editNSum;
};

