// mcf6Dlg.h : ͷ�ļ�
//
#pragma once
#include "afxcmn.h"
#include "afxwin.h"
#include"pcap.h"
#include "utilities.h"
#include "Protocol.h"

// Cmcf6Dlg �Ի���
class Cmcf6Dlg : public CDialog
{
// ����
public:
	Cmcf6Dlg(CWnd* pParent = NULL);	// ��׼���캯��

	/////////////////////////////////////////////[my fuction]//////////////////////////////////////////////
	int lixsniff_initCap();
	int lixsniff_startCap();
	int lixsniff_updateNPacket();
	
	//////////////////////////////////////////////��my data��/////////////////////////////////////////////
	int devCount;
	struct pktcount npacket;	
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *alldev;
	pcap_if_t *dev;
	pcap_t *adhandle;
	pcap_dumper_t *dumpfile;
	char filepath[512];							//	�ļ�����·��
	char filename[64];							//	�ļ�����	

	HANDLE m_ThreadHandle;			//�߳�


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
	CListCtrl m_listCtrl;
	CTreeCtrl m_treeCtrl;
	CButton m_buttonStart;
	CButton m_buttonStop;
	CEdit m_edit;
	CButton m_buttonSave;
	CButton m_buttonRead;
	int npkt;
	CPtrList m_localDataList;				//���汻���ػ�������ݰ�
	CPtrList m_netDataList;					//�����������ֱ�ӻ�ȡ�����ݰ�
	CEdit m_editNTcp;
	CEdit m_editNUdp;
	CEdit m_editNIcmp;
	CEdit m_editNIp;
	CEdit m_editNArp;
	CEdit m_editNHttp;
	CEdit m_editNOther;
	CEdit m_editNSum;
	CEdit m_editNIpv4;
	CEdit m_editIcmpv6;
};
