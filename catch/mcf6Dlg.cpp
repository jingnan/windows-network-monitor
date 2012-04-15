// mcf6Dlg.cpp : 实现文件
//

#include "stdafx.h"
#include "mcf6.h"
#include "mcf6Dlg.h"
#pragma comment(lib, "ws2_32.lib")

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框
DWORD WINAPI lixsinff_CapThread(LPVOID lpParameter);

class CAboutDlg : public CDialog
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

CAboutDlg::CAboutDlg() : CDialog(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialog)
END_MESSAGE_MAP()


// Cmcf6Dlg 对话框




Cmcf6Dlg::Cmcf6Dlg(CWnd* pParent /*=NULL*/)
	: CDialog(Cmcf6Dlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void Cmcf6Dlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(Cmcf6Dlg, CDialog)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
END_MESSAGE_MAP()


// Cmcf6Dlg 消息处理程序

BOOL Cmcf6Dlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		CString strAboutMenu;
		strAboutMenu.LoadString(IDS_ABOUTBOX);
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

	ShowWindow(SW_MINIMIZE);

	// TODO: 在此添加额外的初始化代码
	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void Cmcf6Dlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialog::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void Cmcf6Dlg::OnPaint()
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
		CDialog::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR Cmcf6Dlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


//初始化winpcap
int Cmcf6Dlg::lixsniff_initCap()
{
	devCount = 0;
	if(pcap_findalldevs(&alldev, errbuf) ==-1)
		return -1;
	for(dev=alldev;dev;dev=dev->next)
		devCount++;	
	return 0;
}

//开始捕获
int Cmcf6Dlg::lixsniff_startCap()
{	
	int if_index,filter_index,count;
	u_int netmask;
	struct bpf_program fcode;

	lixsniff_initCap();

	//获得接口和过滤器索引,此段也和界面相关联
	if_index = this->m_comboBox.GetCurSel();
	filter_index = this->m_comboBoxRule.GetCurSel();

	if(0==if_index || CB_ERR == if_index)
	{
		MessageBox(_T("请选择一个合适的网卡接口"));
		return -1;
	}
	if(CB_ERR == filter_index)
	{
		MessageBox(_T("过滤器选择错误"));	
		return -1;
	}

	/*获得选中的网卡接口*/
	dev=alldev;
	for(count=0;count<if_index-1;count++)
		dev=dev->next;
    
	if ((adhandle= pcap_open_live(dev->name,	// 设备名
							 65536,											//捕获数据包长度																					
							 1,													// 混杂模式 (非0意味着是混杂模式)
							 1000,												// 读超时设置
							 errbuf											// 错误信息
							 )) == NULL)
	{
		MessageBox(_T("无法打开接口："+CString(dev->description)));	
		pcap_freealldevs(alldev);                       //释放网络设备列表
		return -1;
	}    

	/*检查是否为以太网*/
	if(pcap_datalink(adhandle)!=DLT_EN10MB)            //pcap_datalink()函数检查数据链路层
	{
		MessageBox(_T("这不适合于非以太网的网络!"));
		pcap_freealldevs(alldev);
		return -1;
	}

	if(dev->addresses!=NULL)	
		netmask=((struct sockaddr_in *)(dev->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		netmask=0xffffff; 

	//编译过滤器
	if(0==filter_index)
	{
		char filter[] = "";
		if (pcap_compile(adhandle, &fcode, filter, 1, netmask) <0 )       //编译过滤器函数
		{
			MessageBox(_T("语法错误，无法编译过滤器"));
			pcap_freealldevs(alldev);
			return -1;
		}
	}else{
		CString str;
		char *filter;
		int len,x;
		this->m_comboBoxRule.GetLBText(filter_index,str);
		len = str.GetLength()+1;
		filter = (char*)malloc(len);
		for(x=0;x<len;x++)
		{
			filter[x] = str.GetAt(x);
		}
		if (pcap_compile(adhandle, &fcode, filter, 1, netmask) <0 )
		{
			MessageBox(_T("语法错误，无法编译过滤器"));
			pcap_freealldevs(alldev);
			return -1;
		}
	}


	//设置过滤器
	if (pcap_setfilter(adhandle, &fcode)<0)                //设置过滤器函数
	{
		MessageBox(_T("设置过滤器错误"));
		pcap_freealldevs(alldev);
		return -1;
	}

	/* 设置数据包存储路径*/
	CFileFind file;
	char thistime[30];
	struct tm *ltime;
	memset(filepath,0,512);
	memset(filename,0,64);

	if(!file.FindFile(_T("SavedData")))
	{
		CreateDirectory(_T("SavedData"),NULL);
	}

	time_t nowtime;
	time(&nowtime);
	ltime=localtime(&nowtime);
	strftime(thistime,sizeof(thistime),"%Y%m%d %H%M%S",ltime);	
	strcpy(filepath,"SavedData\\");
	strcat(filename,thistime);
	strcat(filename,".lix");

	strcat(filepath,filename);
	dumpfile = pcap_dump_open(adhandle, filepath);
	if(dumpfile==NULL)
	{
		MessageBox(_T("文件创建错误！"));
		return -1; 
	}

	pcap_freealldevs(alldev);

	pcap_loop(adhandle,0,packet_handler,NULL); //packet_handler 是回调函数，处理数据包，还没写

	return 1;
}



