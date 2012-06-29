// mcf6Dlg.h : ͷ�ļ�
//
#pragma once
#include "afxcmn.h"
#include "afxwin.h"
#include"pcap.h"
#include "Protocol.h"
#include "utilities.h"

// Cmcf6Dlg �Ի���
class Cmcf6Dlg : public CDialog
{
// ����
public:
	Cmcf6Dlg(CWnd* pParent = NULL);	// ��׼���캯��

	/////////////////////////////////////////////[my fuction]//////////////////////////////////////////////
	int lixsniff_initCap();
	int lixsniff_startCap();
	int lixsniff_updateTree(int index);
	int lixsniff_updateEdit(int index);
	int lixsniff_updateNPacket();
	int lixsniff_saveFile();
	int lixsniff_readFile(CString path);
	
	//////////////////////////////////////////////��my data��/////////////////////////////////////////////
	int devCount;
	struct pktcount npacket;				//�������ݰ�����
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *alldev;
	pcap_if_t *dev;
	pcap_t *adhandle;
	pcap_dumper_t *dumpfile;
	char filepath[512];							//	�ļ�����·��
	char filename[64];							//	�ļ�����							

	HANDLE m_ThreadHandle;			//�߳�

	CPtrList m_pktList;							//���������ŵ�����

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
	CListCtrl m_listCtrl;
	CComboBox m_comboBox;
	CComboBox m_comboBoxRule;
	CTreeCtrl m_treeCtrl;
	CEdit m_edit;
	afx_msg void OnBnClickedButton1();
	afx_msg void OnBnClickedButton2();
	CButton m_buttonStart;
	CButton m_buttonStop;
	CPtrList m_localDataList;				//���汻���ػ�������ݰ�
	CPtrList m_netDataList;					//�����������ֱ�ӻ�ȡ�����ݰ�
	CBitmapButton m_bitButton	;		//ͼƬ��ť
	int npkt;
	afx_msg void OnLvnItemchangedList1(NMHDR *pNMHDR, LRESULT *pResult);
	CEdit m_editNTcp;
	CEdit m_editNUdp;
	CEdit m_editNIcmp;
	CEdit m_editNIp;
	CEdit m_editNArp;
	CEdit m_editNHttp;
	CEdit m_editNOther;
	CEdit m_editNSum;
	afx_msg void OnNMCustomdrawList1(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnBnClickedButton5();
	CButton m_buttonSave;
	CButton m_buttonRead;
	afx_msg void OnBnClickedButton4();
	CEdit m_editNIpv4;
	CEdit m_editIcmpv6;
};
