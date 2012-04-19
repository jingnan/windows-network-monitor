
// mypcapDlg.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "mypcap.h"
#include "mypcapDlg.h"
#include "afxdialogex.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// ����Ӧ�ó��򡰹��ڡ��˵���� CAboutDlg �Ի���

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// �Ի�������
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

// ʵ��
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CmypcapDlg �Ի���




CmypcapDlg::CmypcapDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CmypcapDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CmypcapDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST5, m_listCtrl);
	DDX_Control(pDX, IDC_COMBO1, m_comboBox);
	DDX_Control(pDX, IDC_COMBO2, m_comboBoxRule);
	DDX_Control(pDX, IDC_TREE1, m_treeCtrl);
	DDX_Control(pDX, IDC_EDIT1, m_edit);
	DDX_Control(pDX, IDC_BUTTON3, m_buttonStart);
	DDX_Control(pDX, IDC_BUTTON4, m_buttonStop);
	DDX_Control(pDX, IDC_BUTTON5, m_buttonSave);
	DDX_Control(pDX, IDC_BUTTON6, m_buttonRead);
	DDX_Control(pDX, IDC_EDIT3, m_editNTcp);
	DDX_Control(pDX, IDC_EDIT4, m_editNUdp);
	DDX_Control(pDX, IDC_EDIT5, m_editNIcmp);
	DDX_Control(pDX, IDC_EDIT6, m_editNHttp);
	DDX_Control(pDX, IDC_EDIT7, m_editNArp);
	DDX_Control(pDX, IDC_EDIT8, m_editIcmpv6);
	DDX_Control(pDX, IDC_EDIT9, m_editNIpv6);
	DDX_Control(pDX, IDC_EDIT10, m_editNIpv4);
	DDX_Control(pDX, IDC_EDIT11, m_editNOther);
	DDX_Control(pDX, IDC_EDIT12, m_editNSum);
}

BEGIN_MESSAGE_MAP(CmypcapDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()

END_MESSAGE_MAP()


// CmypcapDlg ��Ϣ�������

BOOL CmypcapDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// ��������...���˵�����ӵ�ϵͳ�˵��С�

	// IDM_ABOUTBOX ������ϵͳ���Χ�ڡ�
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// ���ô˶Ի����ͼ�ꡣ��Ӧ�ó��������ڲ��ǶԻ���ʱ����ܽ��Զ�
	//  ִ�д˲���
	SetIcon(m_hIcon, TRUE);			// ���ô�ͼ��
	SetIcon(m_hIcon, FALSE);		// ����Сͼ��

	// TODO: �ڴ���Ӷ���ĳ�ʼ������
	/*��ʼ����ͷ*/
	m_listCtrl.SetExtendedStyle(LVS_EX_FULLROWSELECT|LVS_EX_GRIDLINES);
	m_listCtrl.InsertColumn(0,_T("���"),3,30);                        //1��ʾ�ң�2��ʾ�У�3��ʾ��
	m_listCtrl.InsertColumn(1,_T("ʱ��"),3,130);
	m_listCtrl.InsertColumn(2,_T("����"),3,72);
	m_listCtrl.InsertColumn(3,_T("ԴMAC��ַ"),3,140);
	m_listCtrl.InsertColumn(4,_T("Ŀ��MAC��ַ"),3,140);
	m_listCtrl.InsertColumn(5,_T("Э��"),3,70);
	m_listCtrl.InsertColumn(6,_T("ԴIP��ַ"),3,145);
	m_listCtrl.InsertColumn(7,_T("Ŀ��IP��ַ"),3,145);

	m_comboBox.AddString(_T("��ѡ��һ�������ӿ�(��ѡ)"));
	m_comboBoxRule.AddString(_T("��ѡ����˹���(��ѡ)"));

	/*��ʼ�����˹����б�*/
	m_comboBoxRule.AddString(_T("tcp"));
	m_comboBoxRule.AddString(_T("udp"));
	m_comboBoxRule.AddString(_T("ip"));
	m_comboBoxRule.AddString(_T("icmp"));
	m_comboBoxRule.AddString(_T("arp"));
	/*Ĭ��ѡ���һ��*/
	m_comboBox.SetCurSel(0);
	m_comboBoxRule.SetCurSel(0);
	/*ֹͣ�뱣�水ť��ֹ�������*/
	m_buttonStop.EnableWindow(FALSE);
	m_buttonSave.EnableWindow(FALSE);

	return TRUE;  // ���ǽ��������õ��ؼ������򷵻� TRUE
}

void CmypcapDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// �����Ի��������С����ť������Ҫ����Ĵ���
//  �����Ƹ�ͼ�ꡣ����ʹ���ĵ�/��ͼģ�͵� MFC Ӧ�ó���
//  �⽫�ɿ���Զ���ɡ�

void CmypcapDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // ���ڻ��Ƶ��豸������

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// ʹͼ���ڹ����������о���
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// ����ͼ��
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}
//���û��϶���С������ʱϵͳ���ô˺���ȡ�ù��
//��ʾ��
HCURSOR CmypcapDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}