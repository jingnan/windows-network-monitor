// mcf6Dlg.h : 头文件
//
#pragma once
#include "afxcmn.h"
#include "afxwin.h"
#include"pcap.h"

// Cmcf6Dlg 对话框
class Cmcf6Dlg : public CDialog
{
// 构造
public:
	Cmcf6Dlg(CWnd* pParent = NULL);	// 标准构造函数

	/////////////////////////////////////////////[my fuction]//////////////////////////////////////////////
	int lixsniff_initCap();
	int lixsniff_startCap();
	
	//////////////////////////////////////////////［my data］/////////////////////////////////////////////
	int devCount;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *alldev;
	pcap_if_t *dev;
	pcap_t *adhandle;
	pcap_dumper_t *dumpfile;
	char filepath[512];							//	文件保存路径
	char filename[64];							//	文件名称							



// 对话框数据
	enum { IDD = IDD_MCF6_DIALOG };

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
	CComboBox m_comboBox;
	CComboBox m_comboBoxRule;
};
