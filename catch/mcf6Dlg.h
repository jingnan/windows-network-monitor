// mcf6Dlg.h : ͷ�ļ�
//
#pragma once
#include "afxcmn.h"
#include "afxwin.h"
#include"pcap.h"

// Cmcf6Dlg �Ի���
class Cmcf6Dlg : public CDialog
{
// ����
public:
	Cmcf6Dlg(CWnd* pParent = NULL);	// ��׼���캯��

	/////////////////////////////////////////////[my fuction]//////////////////////////////////////////////
	int lixsniff_initCap();
	int lixsniff_startCap();
	
	//////////////////////////////////////////////��my data��/////////////////////////////////////////////
	int devCount;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *alldev;
	pcap_if_t *dev;
	pcap_t *adhandle;
	pcap_dumper_t *dumpfile;
	char filepath[512];							//	�ļ�����·��
	char filename[64];							//	�ļ�����							



// �Ի�������
	enum { IDD = IDD_MCF6_DIALOG };

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
	CComboBox m_comboBox;
	CComboBox m_comboBoxRule;
};
