
// mypcapDlg.h : ͷ�ļ�
//

#pragma once
#include "afxcmn.h"
#include "afxwin.h"
#include"pcap.h"

// CmypcapDlg �Ի���
class CmypcapDlg : public CDialogEx
{
// ����
public:
	CmypcapDlg(CWnd* pParent = NULL);	// ��׼���캯��

// �Ի�������
	enum { IDD = IDD_MYPCAP_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV ֧��


// ʵ��
protected:
	HICON m_hIcon;

	// ���ɵ���Ϣӳ�亯��
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

