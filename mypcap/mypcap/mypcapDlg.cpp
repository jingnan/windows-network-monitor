
// mypcapDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "mypcap.h"
#include "mypcapDlg.h"
#include "afxdialogex.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
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


// CmypcapDlg 对话框




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


// CmypcapDlg 消息处理程序

BOOL CmypcapDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
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

	// 设置此对话框的图标。当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码
	/*初始化表头*/
	m_listCtrl.SetExtendedStyle(LVS_EX_FULLROWSELECT|LVS_EX_GRIDLINES);
	m_listCtrl.InsertColumn(0,_T("编号"),3,30);                        //1表示右，2表示中，3表示左
	m_listCtrl.InsertColumn(1,_T("时间"),3,130);
	m_listCtrl.InsertColumn(2,_T("长度"),3,72);
	m_listCtrl.InsertColumn(3,_T("源MAC地址"),3,140);
	m_listCtrl.InsertColumn(4,_T("目的MAC地址"),3,140);
	m_listCtrl.InsertColumn(5,_T("协议"),3,70);
	m_listCtrl.InsertColumn(6,_T("源IP地址"),3,145);
	m_listCtrl.InsertColumn(7,_T("目的IP地址"),3,145);

	m_comboBox.AddString(_T("请选择一个网卡接口(必选)"));
	m_comboBoxRule.AddString(_T("请选择过滤规则(可选)"));

	/*初始化过滤规则列表*/
	m_comboBoxRule.AddString(_T("tcp"));
	m_comboBoxRule.AddString(_T("udp"));
	m_comboBoxRule.AddString(_T("ip"));
	m_comboBoxRule.AddString(_T("icmp"));
	m_comboBoxRule.AddString(_T("arp"));
	/*默认选择第一项*/
	m_comboBox.SetCurSel(0);
	m_comboBoxRule.SetCurSel(0);
	/*停止与保存按钮禁止鼠标输入*/
	m_buttonStop.EnableWindow(FALSE);
	m_buttonSave.EnableWindow(FALSE);

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
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

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CmypcapDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}
//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CmypcapDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}