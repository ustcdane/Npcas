#include "stdafx.h"
#include "Protocolanalysis.h"
#include "ProtocolanalysisDlg.h"
#include "helpdialog.h"
#include "filterdlg.h"
#include "Protocol.h"
#include "sniffer.h"
#include <stdlib.h>
#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif
#define BUFFER_MAX_LENGTH 65536 /* 缓冲区最大长度*/
char g_PacketFilter[1024];
extern  PacketInformation g_packet;
extern EtherHeader g_DisplayEthernet;
extern arpheader g_DisplayARP;
extern IpHeader g_DisplayIP;
extern TcpHeader g_DisplayTCP;
extern UdpHeader g_DisplayUDP;
extern IcmpHeader g_DisplayIcmp;
extern CString g_lwtProgramName;
extern HANDLE g_ProgramValue;
extern char lwtGlobal_FilePath[_MAX_PATH];
extern CProtocolAnalysisDlg *g_pdlg;
bool g_StopThread = TRUE;
HWND g_hWnd;
ProtocolNumber PacketNumber;
/*一下为动态链接库,加载皮肤库的函数*/
/*宏定义函数指针类型 */
typedef int ( WINAPI *SKINH_ATTACHEX)(LPCTSTR strSkinFile,LPCTSTR strPassword);
// 取得SKINH_ATTACHEX函数的地址
SKINH_ATTACHEX pSkinFun = (SKINH_ATTACHEX)::GetProcAddress(LoadLibrary("config\\SkinH.dll"),
														   "SkinH_AttachEx");
// CProtocolAnalysisDlg dialog
CProtocolAnalysisDlg::CProtocolAnalysisDlg(CWnd* pParent /*=NULL*/) : CDialog(CProtocolAnalysisDlg::IDD, pParent)
{
	//{{AFX_DATA_INIT(CProtocolAnalysisDlg)
	//}}AFX_DATA_INIT
	// Note that LoadIcon does not require a subsequent DestroyIcon in Win32
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
	m_SaveDumpFile=true;//初始不保存文件
	//初试化捕获的数据包的个数为0
	m_nPacket=m_nArp=m_nIp=m_nHttp=m_nDns=0;
	m_Ethernet=m_nTcp=m_nUdp=m_nIcmp=0;
	m_pCurrentList = &m_list_common;
	m_pThread = NULL;
	m_nItem=m_iSubItem=-1;
	//取得应用程序当前路径(当打开其他窗口时当前程序路径会变,所以初试化时就获得文件当前路径)
	char appPath[256]={'\0'};
	::GetCurrentDirectory(256, appPath);
	//路径
	m_strFilePath.Format("%s",appPath);
}
void CProtocolAnalysisDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CProtocolAnalysisDlg)
	DDX_Control(pDX, IDC_LIST_DNS, m_list_Dns);
	DDX_Control(pDX, IDC_SKIN, m_picCtrl);
	DDX_Control(pDX, IDC_RICHEDIT, m_EditCtrl);
	DDX_Control(pDX, IDC_LIST_HTTP, m_list_http);
	DDX_Control(pDX, IDC_TREE, m_tree);
	DDX_Control(pDX, IDC_LIST_PPPOE, m_list_ethernet);
	DDX_Control(pDX, IDC_LIST_ICMP, m_list_icmp);
	DDX_Control(pDX, IDC_LIST_UDP, m_list_udp);
	DDX_Control(pDX, IDC_LIST_TCP, m_list_tcp);
	DDX_Control(pDX, IDC_LIST_IP, m_list_ip);
	DDX_Control(pDX, IDC_LIST_ARP, m_list_arp);
	DDX_Control(pDX, IDC_TAB1, m_tab1);
	DDX_Control(pDX, IDC_LIST_COM, m_list_common);
	//}}AFX_DATA_MAP
}
BEGIN_MESSAGE_MAP(CProtocolAnalysisDlg, CDialog)
//{{AFX_MSG_MAP(CProtocolAnalysisDlg)
ON_WM_SYSCOMMAND()
ON_WM_PAINT()
ON_WM_QUERYDRAGICON()
ON_BN_CLICKED(IDC_BUTTON_START, OnButtonStart)
ON_BN_CLICKED(IDC_BUTTON_END, OnButtonStop)
ON_MESSAGE(WM_MY_MESSAGE_COMMON, OnPacket) 
ON_MESSAGE(WM_MY_MESSAGE_ARP, OnArp) 
ON_MESSAGE(WM_MY_MESSAGE_IP, OnIp) 
ON_MESSAGE(WM_MY_MESSAGE_TCP, OnTcp) 
ON_MESSAGE(WM_MY_MESSAGE_UDP, OnUdp) 
ON_MESSAGE(WM_MY_MESSAGE_ICMP, OnIcmp) 
ON_MESSAGE(WM_MY_MESSAGE_ETHERNET, OnEthernet) 
ON_MESSAGE(WM_MY_MESSAGE_HTTP, OnHttp)
ON_MESSAGE(WM_MY_MESSAGE_DNS, OnDns)
ON_NOTIFY(TCN_SELCHANGE, IDC_TAB1, OnSelchangeTab1)
ON_COMMAND(MENU_START, OnStart)
ON_COMMAND(MENU_STOP, OnStop)
ON_COMMAND(MENU_EXIT, OnExit)
ON_COMMAND(MENU_SET_FILETER, OnSetFileter)
ON_WM_DRAWITEM()
ON_WM_MEASUREITEM()
ON_WM_RBUTTONUP()
ON_WM_LBUTTONDOWN()
ON_WM_MOUSEMOVE()
ON_WM_LBUTTONUP()
ON_WM_SIZE()
ON_NOTIFY(NM_CLICK, IDC_TAB1, OnClickTab1)
ON_COMMAND(ID_MENU_OPEN_DUMP_FILE, OnMenuOpenDumpFile)
ON_COMMAND(IDD_menu_Help, OnMenuhelp)
ON_BN_CLICKED(IDC_BUTTON_OPEN_DUMP_FILE, OnButtonOpenDumpFile)
ON_BN_CLICKED(IDC_BUTTON_SET_FILTER, OnButtonSetFilter)
	ON_COMMAND(MENU_SAVE, OnSave)
	ON_WM_CREATE()
	ON_WM_CANCELMODE()
	ON_NOTIFY(NM_CLICK, IDC_LIST_COM, OnClickListCom)
	ON_NOTIFY(NM_CLICK, IDC_LIST_UDP, OnClickListUdp)
	ON_NOTIFY(NM_CLICK, IDC_LIST_TCP, OnClickListTcp)
	ON_NOTIFY(NM_CLICK, IDC_LIST_IP, OnClickListIp)
	ON_NOTIFY(NM_CLICK, IDC_LIST_ARP, OnClickListArp)
	ON_NOTIFY(NM_CLICK, IDC_LIST_PPPOE, OnClickListEthernet)
	ON_BN_CLICKED(IDC_BTCLEAR, OnBtclear)
	ON_COMMAND(MENU_RESTART, OnRestart)
	ON_COMMAND(IDD_menu_First, OnmenuFirst)
	ON_COMMAND(IDD_menu_Last, OnmenuLast)
	ON_COMMAND(IDD_menu_Center, OnmenuCenter)
	ON_COMMAND(ID_MENU_SHOW, OnMenuShow)
	ON_COMMAND(ID_MENU_QUIT, OnMenuQuit)
	ON_COMMAND(MENU_IF_SAVE, OnIfSave)
	ON_NOTIFY(NM_CLICK, IDC_LIST_HTTP, OnClickListHttp)
	ON_NOTIFY(NM_CLICK, IDC_LIST_ICMP, OnClickListIcmp)
	ON_NOTIFY(NM_RCLICK, IDC_LIST_COM, OnRclickListCom)
	ON_COMMAND(ID_COPY, OnCopy)
	ON_NOTIFY(NM_RCLICK, IDC_LIST_PPPOE, OnRclickListPppoe)
	ON_NOTIFY(NM_RCLICK, IDC_LIST_IP, OnRclickListIp)
	ON_NOTIFY(NM_RCLICK, IDC_LIST_ARP, OnRclickListArp)
	ON_NOTIFY(NM_RCLICK, IDC_LIST_ICMP, OnRclickListIcmp)
	ON_NOTIFY(NM_RCLICK, IDC_LIST_TCP, OnRclickListTcp)
	ON_NOTIFY(NM_RCLICK, IDC_LIST_UDP, OnRclickListUdp)
	ON_NOTIFY(NM_RCLICK, IDC_LIST_HTTP, OnRclickListHttp)
	ON_BN_CLICKED(IDC_SKIN, OnSkin)
	ON_COMMAND(ID_SKIN_1, OnSkin1)
	ON_COMMAND(ID_SKIN_2, OnSkin2)
	ON_COMMAND(ID_SKIN_3, OnSkin3)
	ON_COMMAND(ID_SKIN_4, OnSkin4)
	ON_COMMAND(ID_SKIN_RE, OnSkinRe)
	ON_NOTIFY(NM_DBLCLK, IDC_TREE, OnDblclkTree)
	ON_NOTIFY(NM_CLICK, IDC_LIST_DNS, OnClickListDns)
ON_MESSAGE( WM_TRAYICON_MSG,OnTrayCallBackMsg)
ON_COMMAND(MENU_HELP, OnHelp)
ON_WM_NCPAINT()
	ON_NOTIFY(NM_RCLICK, IDC_LIST_DNS, OnRclickListDns)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()
// CProtocolAnalysisDlg message handlers
BOOL CProtocolAnalysisDlg::OnInitDialog()
{	
	CDialog::OnInitDialog();
	AfxGetMainWnd()->CenterWindow(); 
	SetProp(m_hWnd, g_lwtProgramName, g_ProgramValue);
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
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon
	if(pSkinFun)
	{
		// 加载皮肤文件
		pSkinFun(_T("skin\\pixos.she"), NULL);
	}
	else
	{
		MessageBox(_T("皮肤库加载失败!"),_T("缺少SkinH.dll"));
	}
	UpdateData(TRUE);
	UpdateData(FALSE);
	m_list_common.InsertColumn(0, "序号", LVCFMT_LEFT, 300, 1);
	m_list_common.InsertColumn(1, "源MAC", LVCFMT_LEFT, 300, 1);
	m_list_common.InsertColumn(2, "目的MAC", LVCFMT_LEFT, 300, 1);
	m_list_common.InsertColumn(3, "协议类型", LVCFMT_LEFT, 300, 1);
	m_list_common.InsertColumn(4, "源IP", LVCFMT_LEFT, 300, 1);
	m_list_common.InsertColumn(5, "源端口", LVCFMT_LEFT, 300, 1);
	m_list_common.InsertColumn(6, "目的IP", LVCFMT_LEFT, 300, 1);
	m_list_common.InsertColumn(7, "目的端口", LVCFMT_LEFT, 300, 1);
	m_list_common.SetColumnWidth(0, 40);
	m_list_common.SetColumnWidth(1, 120);
	m_list_common.SetColumnWidth(2, 120);
	m_list_common.SetColumnWidth(3, 60);
	m_list_common.SetColumnWidth(4, 110);
	m_list_common.SetColumnWidth(5, 50);
	m_list_common.SetColumnWidth(6, 110);
	m_list_common.SetColumnWidth(7, 60);
	ListView_SetExtendedListViewStyle(m_list_common.m_hWnd,
		LVS_EX_FULLROWSELECT |
		LVS_EX_FLATSB |
		LVS_EX_GRIDLINES |
		LVS_EX_HEADERDRAGDROP);

	m_list_ethernet.InsertColumn(0, "序号", LVCFMT_LEFT, 300, 1);
	m_list_ethernet.InsertColumn(1, "源MAC地址", LVCFMT_LEFT, 300, 1);
	m_list_ethernet.InsertColumn(2, "目的MAC地址", LVCFMT_LEFT, 300, 1);
	m_list_ethernet.InsertColumn(3, "协议类型", LVCFMT_LEFT, 300, 1);
	m_list_ethernet.SetColumnWidth(0, 40);
	m_list_ethernet.SetColumnWidth(1, 120);
	m_list_ethernet.SetColumnWidth(2, 120);
	m_list_ethernet.SetColumnWidth(3, 120);
	m_list_ethernet.SetColumnWidth(4, 120);
	ListView_SetExtendedListViewStyle(m_list_ethernet.m_hWnd,
		LVS_EX_FULLROWSELECT |
		LVS_EX_FLATSB |
		LVS_EX_GRIDLINES |
		LVS_EX_HEADERDRAGDROP);

	m_list_arp.InsertColumn(0, "序号", LVCFMT_LEFT, 300, 1);
	m_list_arp.InsertColumn(1, "硬件地址类型", LVCFMT_LEFT, 300, 1);
	m_list_arp.InsertColumn(2, "协议地址类型", LVCFMT_LEFT, 300, 1);
	m_list_arp.InsertColumn(3, "硬件地址长度", LVCFMT_LEFT, 300, 1);
	m_list_arp.InsertColumn(4, "协议地址长度", LVCFMT_LEFT, 300, 1);
	m_list_arp.InsertColumn(5, "ARP操作", LVCFMT_LEFT, 300, 1);
	m_list_arp.InsertColumn(6, "备注", LVCFMT_LEFT, 300, 1);
	m_list_arp.InsertColumn(7, "发送端IP", LVCFMT_LEFT, 300, 1);
	m_list_arp.InsertColumn(8, "目的端Ip", LVCFMT_LEFT, 300, 1);
	m_list_arp.SetColumnWidth(0, 40);
	m_list_arp.SetColumnWidth(1, 86);
	m_list_arp.SetColumnWidth(2, 86);
	m_list_arp.SetColumnWidth(3, 84);
	m_list_arp.SetColumnWidth(4, 84);
	m_list_arp.SetColumnWidth(5, 60);
	m_list_arp.SetColumnWidth(6, 100);
	m_list_arp.SetColumnWidth(7, 120);
	m_list_arp.SetColumnWidth(8, 120);
	ListView_SetExtendedListViewStyle(m_list_arp.m_hWnd,
		LVS_EX_FULLROWSELECT |
		LVS_EX_GRIDLINES |
		LVS_EX_FLATSB |
		LVS_EX_HEADERDRAGDROP);

	m_list_ip.InsertColumn(0, "序号", LVCFMT_LEFT, 300, 1);
	m_list_ip.InsertColumn(1, "协议版本", LVCFMT_LEFT, 300, 1);
	m_list_ip.InsertColumn(2, "首部长度", LVCFMT_LEFT, 300, 1);
	m_list_ip.InsertColumn(3, "服务质量", LVCFMT_LEFT, 300, 1);
	m_list_ip.InsertColumn(4, "IP长度", LVCFMT_LEFT, 300, 1);
	m_list_ip.InsertColumn(5, "ID号(标识)", LVCFMT_LEFT, 300, 1);
	m_list_ip.InsertColumn(6, "标志", LVCFMT_LEFT, 300, 1);
	m_list_ip.InsertColumn(7, "偏移量", LVCFMT_LEFT, 300, 1);
	m_list_ip.InsertColumn(8, "生存周期", LVCFMT_LEFT, 300, 1);
	m_list_ip.InsertColumn(9, "协议类型", LVCFMT_LEFT, 300, 1);
	m_list_ip.InsertColumn(10, "校验和", LVCFMT_LEFT, 300, 1);
	m_list_ip.InsertColumn(11, "源IP地址", LVCFMT_LEFT, 300, 1);
	m_list_ip.InsertColumn(12, "目的IP地址", LVCFMT_LEFT, 300, 1);
	m_list_ip.SetColumnWidth(0, 40);
	m_list_ip.SetColumnWidth(1, 120);
	m_list_ip.SetColumnWidth(2, 120);
	m_list_ip.SetColumnWidth(3, 120);
	m_list_ip.SetColumnWidth(4, 120);
	m_list_ip.SetColumnWidth(5, 80);
	m_list_ip.SetColumnWidth(6, 60);
	m_list_ip.SetColumnWidth(7, 110);
	m_list_ip.SetColumnWidth(8, 110);
	m_list_ip.SetColumnWidth(9, 110);
	m_list_ip.SetColumnWidth(10, 110);
	m_list_ip.SetColumnWidth(11, 110);
	m_list_ip.SetColumnWidth(12, 110);
	ListView_SetExtendedListViewStyle(m_list_ip.m_hWnd,
		LVS_EX_FULLROWSELECT |
		LVS_EX_GRIDLINES |
		LVS_EX_FLATSB |
		LVS_EX_HEADERDRAGDROP);
	m_list_icmp.InsertColumn(0, "序号", LVCFMT_LEFT, 300, 1);
	m_list_icmp.InsertColumn(1, "类型", LVCFMT_LEFT, 300, 1);
	m_list_icmp.InsertColumn(2, "代码", LVCFMT_LEFT, 300, 1);
	m_list_icmp.InsertColumn(3, "校验和", LVCFMT_LEFT, 300, 1);
	m_list_icmp.InsertColumn(4, "说明", LVCFMT_LEFT, 300, 1);
	m_list_icmp.SetColumnWidth(0, 40);
	m_list_icmp.SetColumnWidth(1, 120);
	m_list_icmp.SetColumnWidth(2, 120);
	m_list_icmp.SetColumnWidth(3, 120);
	m_list_icmp.SetColumnWidth(4, 120);
	ListView_SetExtendedListViewStyle(m_list_icmp.m_hWnd,
		LVS_EX_FULLROWSELECT |
		LVS_EX_GRIDLINES |
		LVS_EX_FLATSB |
		LVS_EX_HEADERDRAGDROP);
	
	m_list_tcp.InsertColumn(0, "序号", LVCFMT_LEFT, 300, 1);
	m_list_tcp.InsertColumn(1, "源端口", LVCFMT_LEFT, 300, 1);
	m_list_tcp.InsertColumn(2, "目的端口", LVCFMT_LEFT, 300, 1);
	m_list_tcp.InsertColumn(3, "序列号", LVCFMT_LEFT, 300, 1);
	m_list_tcp.InsertColumn(4, "确认号", LVCFMT_LEFT, 300, 1);
	m_list_tcp.InsertColumn(5, "首部长度", LVCFMT_LEFT, 300, 1);
	m_list_tcp.InsertColumn(6, "保留", LVCFMT_LEFT, 300, 1);
	m_list_tcp.InsertColumn(7, "标志", LVCFMT_LEFT, 300, 1);
	m_list_tcp.InsertColumn(8, "窗口", LVCFMT_LEFT, 300, 1);
	m_list_tcp.InsertColumn(9, "校验和", LVCFMT_LEFT, 300, 1);
	m_list_tcp.InsertColumn(10, "紧急指针", LVCFMT_LEFT, 300, 1);
	m_list_tcp.SetColumnWidth(0, 40);
	m_list_tcp.SetColumnWidth(1, 120);
	m_list_tcp.SetColumnWidth(2, 120);
	m_list_tcp.SetColumnWidth(3, 120);
	m_list_tcp.SetColumnWidth(4, 120);
	m_list_tcp.SetColumnWidth(5, 60);
	m_list_tcp.SetColumnWidth(6, 80);
	m_list_tcp.SetColumnWidth(7, 120);
	m_list_tcp.SetColumnWidth(8, 100);
	m_list_tcp.SetColumnWidth(9, 110);
	m_list_tcp.SetColumnWidth(10, 110);
	ListView_SetExtendedListViewStyle(m_list_tcp.m_hWnd,
		LVS_EX_FULLROWSELECT |
		LVS_EX_GRIDLINES |
		LVS_EX_FLATSB |
		LVS_EX_HEADERDRAGDROP);
	m_list_udp.InsertColumn(0, "序号", LVCFMT_LEFT, 300, 1);
	m_list_udp.InsertColumn(1, "源端口", LVCFMT_LEFT, 300, 1);
	m_list_udp.InsertColumn(2, "目的端口", LVCFMT_LEFT, 300, 1);
	m_list_udp.InsertColumn(3, "长度", LVCFMT_LEFT, 300, 1);
	m_list_udp.InsertColumn(4, "校验和", LVCFMT_LEFT, 300, 1);
	m_list_udp.SetColumnWidth(0, 40);
	m_list_udp.SetColumnWidth(1, 120);
	m_list_udp.SetColumnWidth(2, 120);
	m_list_udp.SetColumnWidth(3, 120);
	m_list_udp.SetColumnWidth(4, 120);
	ListView_SetExtendedListViewStyle(m_list_udp.m_hWnd,
		LVS_EX_FULLROWSELECT |
		LVS_EX_GRIDLINES |
		LVS_EX_FLATSB |
		LVS_EX_HEADERDRAGDROP);

	m_list_http.InsertColumn(0, "序号", LVCFMT_LEFT, 300, 1);
	m_list_http.InsertColumn(1, "源IP地址", LVCFMT_LEFT, 300, 1);
	m_list_http.InsertColumn(2, "目的IP地址", LVCFMT_LEFT, 300, 1);
	m_list_http.InsertColumn(3, "信息", LVCFMT_LEFT, 300, 1);
	m_list_http.SetColumnWidth(0, 40);
	m_list_http.SetColumnWidth(1, 140);
	m_list_http.SetColumnWidth(2, 140);
	m_list_http.SetColumnWidth(3, 400);
	ListView_SetExtendedListViewStyle(m_list_http.m_hWnd,
		LVS_EX_FULLROWSELECT |
		LVS_EX_GRIDLINES |
		LVS_EX_FLATSB |
		LVS_EX_HEADERDRAGDROP);

	m_list_Dns.InsertColumn(0, "序号", LVCFMT_LEFT, 300, 1);
	m_list_Dns.InsertColumn(1, "标识", LVCFMT_LEFT, 300, 1);
	m_list_Dns.InsertColumn(2, "QR(标志)", LVCFMT_LEFT, 300, 1);
	m_list_Dns.InsertColumn(3, "opcode(标志)", LVCFMT_LEFT, 300, 1);
	m_list_Dns.InsertColumn(4, "AA(标志)", LVCFMT_LEFT, 300, 1);
	m_list_Dns.InsertColumn(5, "TC(标志)", LVCFMT_LEFT, 300, 1);
	m_list_Dns.InsertColumn(6, "RD(标志)", LVCFMT_LEFT, 300, 1);
	m_list_Dns.InsertColumn(7, "RA(标志)", LVCFMT_LEFT, 300, 1);
	m_list_Dns.InsertColumn(8, "zero(标志)", LVCFMT_LEFT, 300, 1);
	m_list_Dns.InsertColumn(9, "rcode(标志)", LVCFMT_LEFT, 300, 1);
	m_list_Dns.InsertColumn(10, "问题数", LVCFMT_LEFT, 300, 1);
	m_list_Dns.InsertColumn(11, "资源记录数", LVCFMT_LEFT, 300, 1);
	m_list_Dns.InsertColumn(12, "授权资源记录数", LVCFMT_LEFT, 300, 1);
	m_list_Dns.InsertColumn(13, "额外资源记录数", LVCFMT_LEFT, 300, 1);
	m_list_Dns.SetColumnWidth(0, 40);
	m_list_Dns.SetColumnWidth(1, 80);
	m_list_Dns.SetColumnWidth(2, 60);
	m_list_Dns.SetColumnWidth(3, 90);
	m_list_Dns.SetColumnWidth(4, 70);
	m_list_Dns.SetColumnWidth(5, 70);
	m_list_Dns.SetColumnWidth(6, 70);
	m_list_Dns.SetColumnWidth(7, 70);
	m_list_Dns.SetColumnWidth(8, 70);
	m_list_Dns.SetColumnWidth(9, 100);
	m_list_Dns.SetColumnWidth(10, 80);
	m_list_Dns.SetColumnWidth(11, 100);
	m_list_Dns.SetColumnWidth(12, 100);
	m_list_Dns.SetColumnWidth(13, 100);
	ListView_SetExtendedListViewStyle(m_list_Dns.m_hWnd,
		LVS_EX_FULLROWSELECT |
		LVS_EX_GRIDLINES |
		LVS_EX_FLATSB |
		LVS_EX_HEADERDRAGDROP);
	//设置列表框背景颜色,字体颜色
	m_list_common.SetBkColor (RGB(135,202,235));
	m_list_ethernet.SetBkColor (RGB(225,245,245));
	m_list_arp.SetBkColor (RGB(192,243,204));
	m_list_ip.SetBkColor (RGB(189,213,247));
	m_list_tcp.SetBkColor (RGB(10,100,100));
	m_list_udp.SetBkColor (RGB(177,151,225));
	m_list_icmp.SetBkColor (RGB(148,228,190));
	m_list_Dns.SetBkColor (RGB(189,213,200));
	m_list_common.SetTextBkColor  (RGB(135,202,235));
	m_list_ethernet.SetTextBkColor (RGB(225,245,245));
	m_list_arp.SetTextBkColor (RGB(192,243,204));
	m_list_ip.SetTextBkColor (RGB(189,213,247));
	m_list_tcp.SetTextBkColor (RGB(10,100,100));
	m_list_udp.SetTextBkColor(RGB(177,151,225));
	m_list_icmp.SetTextBkColor(RGB(148,228,190));
	m_list_Dns.SetTextBkColor (RGB(189,213,200));
	m_list_common.SetTextColor (RGB(200,10,100));
	m_list_arp.SetTextColor(RGB(192,0,204));
	m_list_ip.SetTextColor(RGB(150,0,0));
	m_list_tcp.SetTextColor (RGB(255,242,69));
	m_list_udp.SetTextColor(RGB(0,0,0));
	m_list_icmp.SetTextColor(RGB(28,43,227));
	m_list_ethernet.SetTextColor (RGB(28,43,227));
	m_list_Dns.SetTextColor(RGB(180,0,0));
	CTabCtrl* pTab = (CTabCtrl*) GetDlgItem(IDC_TAB1);
	CRect rectWnd;
	pTab->GetWindowRect(rectWnd);
	m_tab1.InsertItem(0, "网络信息  ", 0);	
	m_tab1.InsertItem(1, "以太网协议信息", 1);
	m_tab1.InsertItem(2, "ARP/RARP协议信息  ", 2);
	m_tab1.InsertItem(3, "IP协议信息  ", 3);
	m_tab1.InsertItem(4, "ICMP协议信息  ", 4);
	m_tab1.InsertItem(5, "TCP协议信息  ", 5);
	m_tab1.InsertItem(6, "UDP协议信息  ",6);	
	m_tab1.InsertItem(7, "HTTP协议信息  ",7);
	m_tab1.InsertItem(8, "DNS协议信息  ",8);

	CRect rect;
	GetClientRect(&rect);
	CRect newrect(rect);
	newrect.top =rect.top +30;
	m_tab1.MoveWindow (newrect);
	CRect rect1, rect2;
	m_tab1.GetWindowRect(rect1); 
	m_tab1.GetItemRect(0, rect2); 
	ScreenToClient(rect1);
	rect1.left += 2;
	rect1.top += rect2.Height() + 3;
	int h=(rect1.Height() - rect2.Height())/2-2;
	m_picCtrl.SetWindowPos(NULL, rect1.right-60, rect1.top-50,30,
		 30, NULL);
	m_picCtrl.ShowWindow(SW_SHOW);
	m_list_common.SetWindowPos(NULL, rect1.left, rect1.top, rect1.Width(),
		 h, NULL); 
	m_list_common.ShowWindow(SW_SHOW);	 
	m_list_arp.SetWindowPos(NULL, rect1.left, rect1.top, rect1.Width(),
		h, NULL); 
	m_list_arp.ShowWindow(SW_HIDE);	 
	m_list_ip.SetWindowPos(NULL, rect1.left, rect1.top, rect1.Width(),
		h, NULL); 
	m_list_ip.ShowWindow(SW_HIDE);	 
	m_list_tcp.SetWindowPos(NULL, rect1.left, rect1.top, rect1.Width(),
		h, NULL); 
	m_list_tcp.ShowWindow(SW_HIDE);
	m_list_udp.SetWindowPos(NULL, rect1.left, rect1.top, rect1.Width(),
		h , NULL); 
	m_list_udp.ShowWindow(SW_HIDE);	 
	m_list_icmp.SetWindowPos(NULL, rect1.left, rect1.top, rect1.Width(),
		h, NULL); 
	m_list_icmp.ShowWindow(SW_HIDE);
	m_list_ethernet.SetWindowPos(NULL, rect1.left, rect1.top, rect1.Width(),
		h , NULL); 
	m_list_ethernet.ShowWindow(SW_HIDE);
	m_list_http.SetWindowPos(NULL, rect1.left, rect1.top, rect1.Width(),
		h , NULL); 
	m_list_http.ShowWindow(SW_HIDE);
	m_list_Dns.SetWindowPos(NULL, rect1.left, rect1.top, rect1.Width(),
		h , NULL); 
	m_list_Dns.ShowWindow(SW_HIDE);
	////////////////////////////////////TreeCtrl控件///////////////
	m_ImageList.Create(16,16,ILC_COLOR16,12, 0);
	m_ImageList.Add(AfxGetApp()->LoadIcon(IDI_ICON_FRAM));
	m_ImageList.Add(AfxGetApp()->LoadIcon(IDI_ICON_H));
	m_ImageList.Add(AfxGetApp()->LoadIcon(IDI_ICON_SUM));
	m_ImageList.Add(AfxGetApp()->LoadIcon(IDI_ICON_SR_DE));
	m_ImageList.Add(AfxGetApp()->LoadIcon(IDI_ICON_TYPE));
	m_ImageList.Add(AfxGetApp()->LoadIcon(IDI_ICON_PRO));
	m_ImageList.Add(AfxGetApp()->LoadIcon(IDI_ICON_LEN));
	m_ImageList.Add(AfxGetApp()->LoadIcon(IDI_ICON_OPER));
	m_ImageList.Add(AfxGetApp()->LoadIcon(IDI_ICON_TTL));
	m_ImageList.Add(AfxGetApp()->LoadIcon(IDI_ICON_com));
	m_ImageList.Add(AfxGetApp()->LoadIcon(IDI_ICON_TEXT));
	m_tree.SetImageList(&m_ImageList,LVSIL_NORMAL );
	m_tree.SetTextColor(RGB(60,100,60));
  //编辑控件
		//初始化字体及颜色
	ZeroMemory(&m_cf, sizeof(CHARFORMAT));
	m_cf.cbSize = sizeof(CHARFORMAT);
	m_cf.dwMask = CFM_BOLD | CFM_COLOR | CFM_FACE |
		CFM_ITALIC | CFM_SIZE | CFM_UNDERLINE;
	m_cf.dwEffects = 0;
	m_cf.yHeight = 16*15;//文字高度
	m_cf.crTextColor = RGB(80, 10, 25); //文字颜色
	strcpy(m_cf.szFaceName ,_T("隶书"));//设置字体
	m_EditCtrl.SetDefaultCharFormat(m_cf);

	m_tree.SetWindowPos(NULL, rect1.left,rect2.bottom+h+12, rect1.Width()/2,
			h , NULL); 
	m_tree.ShowWindow(SW_SHOW);
	m_EditCtrl.SetWindowPos(NULL, rect1.left+rect1.Width()/2 +3,rect2.bottom+h+12 , rect1.Width()/2,
			h , NULL); 
	m_EditCtrl.ShowWindow(SW_SHOW);
	// Get the popup menu 
	CMenu* mmenu = GetMenu();
	m_Psubmenu = mmenu->GetSubMenu(2);// 获得子菜单
	// 默认设置sub(0) 选中
	m_Psubmenu->CheckMenuItem(MENU_IF_SAVE, MF_CHECKED | MF_BYCOMMAND);
	g_hWnd = GetSafeHwnd();
	SetWindowText("网络包截获分析系统"); 
	CButton *p=(CButton*)GetDlgItem (IDC_BUTTON_END);
	p->EnableWindow (FALSE);
	CMenu *pp=(CMenu *)GetMenu();
	pp->EnableMenuItem (MENU_STOP,TRUE);
	ShowWindow(SW_MAXIMIZE); 
	g_pdlg=this;
	return TRUE;  // return TRUE  unless you set the focus to a control
}

void CProtocolAnalysisDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
 if ((nID & 0xFFF0) == SC_CLOSE)
	{
		OnExit();
	}
	else if ((nID & 0xFFF0) == SC_MAXIMIZE)//最大化
	{
		ShowWindow(SW_MAXIMIZE);
		CRect rect1, rect2;
		int h;
		m_tab1.GetWindowRect(rect1); 
		m_tab1.GetItemRect(0, rect2); 
		ScreenToClient(rect1);
		rect1.left += 2;
		rect1.top += rect2.Height() + 3;
		h=(rect1.Height() - rect2.Height())/2-2;
		m_picCtrl.SetWindowPos(NULL, rect1.right-60, rect1.top-50,30,
		 30, NULL);
		m_picCtrl.ShowWindow(SW_SHOW);
		m_list_common.SetWindowPos(NULL, rect1.left, rect1.top, rect1.Width(),
			h , NULL); 
		m_list_ethernet.SetWindowPos(NULL, rect1.left, rect1.top, rect1.Width(),
			h , NULL); 
		m_list_arp.SetWindowPos(NULL, rect1.left, rect1.top, rect1.Width(),
			h , NULL); 
		m_list_ip.SetWindowPos(NULL, rect1.left, rect1.top, rect1.Width(),
			h, NULL); 
		m_list_tcp.SetWindowPos(NULL, rect1.left, rect1.top, rect1.Width(),
			h, NULL); 
		m_list_udp.SetWindowPos(NULL, rect1.left, rect1.top, rect1.Width(),
			h , NULL); 
		m_list_icmp.SetWindowPos(NULL, rect1.left, rect1.top, rect1.Width(),
			h , NULL); 
		m_list_http.SetWindowPos(NULL, rect1.left, rect1.top, rect1.Width(),
			h , NULL); 
		m_list_Dns.SetWindowPos(NULL, rect1.left, rect1.top, rect1.Width(),
			h , NULL); 
		m_tree.SetWindowPos(NULL, rect1.left,rect2.bottom+h+28, rect1.Width()/2,
			h , NULL); 
		m_tree.ShowWindow(SW_SHOW);
		m_EditCtrl.SetWindowPos(NULL, rect1.left+rect1.Width()/2 +3,rect2.bottom+h+28 , rect1.Width()/2,
			h , NULL); 
		m_EditCtrl.ShowWindow(SW_SHOW);
	}
	else if ((nID & 0xFFF0) == SC_MINIMIZE)
	{
		TrayMyIcon(); // 最小化时任务托盘
	}
	else
	{
		CDialog::OnSysCommand(nID, lParam);
	}
}

void CProtocolAnalysisDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting
		SendMessage(WM_ICONERASEBKGND, (WPARAM) dc.GetSafeHdc(), 0);
		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;
		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}
HCURSOR CProtocolAnalysisDlg::OnQueryDragIcon()
{
	return (HCURSOR) m_hIcon;
}


UINT ThreadPacketCapture(LPVOID pParam)//包捕获线程
{
	CapturePacket();
	return 0;
}

UINT ThreadReadFile(LPVOID pParam)//读取文件线程
{
	DumpFileOperation();
	return 0;
}

LRESULT CProtocolAnalysisDlg::OnPacket(WPARAM wParam, LPARAM lParam)
{
	char str[10]; 
	sprintf(str, "%d", m_nPacket);
	m_list_common.InsertItem(m_nPacket,str);
	/*添加附加据,即数将列表项与存放原始数据包的堆地址指针关联*/
	m_list_common.SetItemData(m_nPacket,(DWORD)lParam);
	m_list_common.SetItemText(m_nPacket, 0, str);
	m_list_common.SetItemText(m_nPacket, 1, g_packet.SourceMac);
	m_list_common.SetItemText(m_nPacket, 2, g_packet.DestinationMac);
	m_list_common.SetItemText(m_nPacket, 3, g_packet.NetType);
	m_list_common.SetItemText(m_nPacket, 4, g_packet.SourceAddr);
	m_list_common.SetItemText(m_nPacket, 5, g_packet.SourcePort);
	m_list_common.SetItemText(m_nPacket, 6, g_packet.DestinationAddr);
	m_list_common.SetItemText(m_nPacket, 7, g_packet.DestinationPort);
	UpdateData(FALSE);
	PacketNumber.count = m_nPacket+1;
	CStatic *p=(CStatic *)GetDlgItem(IDC_STATIC_PACKET_COUNT);
	CString strnum;
	strnum.Format("截获的包数目:%d",PacketNumber.count);
	p->SetWindowText (strnum);
	UpdateData(FALSE);
	m_nPacket++;
	if (m_nPacket==1600)//截获的数据包的上限
	{
		if (g_StopThread == TRUE)
		{
			return 0;
		}
		g_StopThread = TRUE;
		CButton *p=(CButton*)GetDlgItem (IDC_BUTTON_END);
		p->EnableWindow (FALSE);
		CMenu *pp=(CMenu *)GetMenu();
		pp->EnableMenuItem (MENU_STOP,TRUE);
		CButton *p2=(CButton*)GetDlgItem (IDC_BUTTON_START);
		p2->EnableWindow (TRUE);
		CMenu *pp2=(CMenu *)GetMenu();
		pp2->EnableMenuItem (MENU_START,FALSE);
	}
	return  0;
}

LRESULT CProtocolAnalysisDlg::OnEthernet(WPARAM wParam, LPARAM lParam)
{
	char str[10]; 
	sprintf(str, "%d", m_Ethernet);
	m_list_ethernet.InsertItem(m_Ethernet,str);
	/*添加附加据,即将列表项与存放原始数据包的堆地址指针关联*/
	m_list_ethernet.SetItemData(m_Ethernet,(DWORD)lParam);
	m_list_ethernet.SetItemText(m_Ethernet, 0, str);
	m_list_ethernet.SetItemText(m_Ethernet, 1, g_DisplayEthernet.SourceMac);
	m_list_ethernet.SetItemText(m_Ethernet, 2, g_DisplayEthernet.DestinationMac);
	m_list_ethernet.SetItemText(m_Ethernet, 3, g_DisplayEthernet.NetType);
	UpdateData(FALSE);
	PacketNumber.ethernet = m_Ethernet+1;
	m_Ethernet++;  
	return  0;
}

LRESULT CProtocolAnalysisDlg::OnArp(WPARAM wParam, LPARAM lParam)
{ 
	char str[10]; 
	sprintf(str, "%d", m_nArp);
	m_tree.InsertItem(_T("协议类型:arp"), 5,5,m_MacHdrRoot,TVI_LAST);
	m_list_arp.InsertItem(m_nArp,str);
	/*添加附加据,即将列表项与存放原始数据包的堆地址指针关联*/
	m_list_arp.SetItemData(m_nArp,(DWORD)lParam);
	m_list_arp.SetItemText(m_nArp, 0, str);
	m_list_arp.SetItemText(m_nArp, 1, g_DisplayARP.Hardware);
	m_list_arp.SetItemText(m_nArp, 2, g_DisplayARP.Protocol);
	m_list_arp.SetItemText(m_nArp, 3, g_DisplayARP.HardwareLength);
	m_list_arp.SetItemText(m_nArp, 4, g_DisplayARP.ProtocolLength);
	m_list_arp.SetItemText(m_nArp, 5, g_DisplayARP.OperationCode);
	m_list_arp.SetItemText(m_nArp, 6, g_DisplayARP.OperationInformatin);
	m_list_arp.SetItemText(m_nArp, 7, g_DisplayARP.SourceAddr);
	m_list_arp.SetItemText(m_nArp, 8, g_DisplayARP.DestinationAddr);
	UpdateData(FALSE);
	PacketNumber.arp = m_nArp+1;	
	m_nArp++;  
	return  0;
}

LRESULT CProtocolAnalysisDlg::OnIp(WPARAM wParam, LPARAM lParam)
{
	RAW_PACKET *pRawPacket = (RAW_PACKET *)lParam;
	pRawPacket->ip_seq = m_nIp;
	char str[10]; 
	sprintf(str, "%d", m_nIp);
	m_tree.InsertItem(_T("协议类型:Ip"), 5,5,m_MacHdrRoot,TVI_LAST);
	m_list_ip.InsertItem(m_nIp,str);
	/*添加附加据,即将列表项与存放原始数据包的堆地址指针关联*/
	m_list_ip.SetItemData(m_nIp,(DWORD)lParam);
	m_list_ip.SetItemText(m_nIp, 0, str);
	m_list_ip.SetItemText(m_nIp, 1, g_DisplayIP.Version);
	m_list_ip.SetItemText(m_nIp, 2, g_DisplayIP.HeaderLength);
	m_list_ip.SetItemText(m_nIp, 3, g_DisplayIP.Tos);
	m_list_ip.SetItemText(m_nIp, 4, g_DisplayIP.Length);
	m_list_ip.SetItemText(m_nIp, 5, g_DisplayIP.Ident);
	m_list_ip.SetItemText(m_nIp, 6, g_DisplayIP.Flags);
	m_list_ip.SetItemText(m_nIp, 7, g_DisplayIP.Offset);
	m_list_ip.SetItemText(m_nIp, 8, g_DisplayIP.TTL);
	m_list_ip.SetItemText(m_nIp, 9, g_DisplayIP.Protocol);
	m_list_ip.SetItemText(m_nIp, 10, g_DisplayIP.Checksum);
	m_list_ip.SetItemText(m_nIp, 11, g_DisplayIP.SourceAddr);
	m_list_ip.SetItemText(m_nIp, 12, g_DisplayIP.DestinationAddr);
	UpdateData(FALSE);
	PacketNumber.ip = m_nIp+1;
	m_nIp++;  
	return  0;
}
LRESULT CProtocolAnalysisDlg::OnIcmp(WPARAM wParam, LPARAM lParam)
{ 
	char str[10]; 
	sprintf(str, "%d", m_nIcmp);
	m_list_icmp.InsertItem(m_nIcmp,str);
	/*添加附加据,即数将列表项与存放原始数据包的堆地址指针关联*/
	m_list_icmp.SetItemData(m_nIcmp,(DWORD)lParam);
	m_list_icmp.SetItemText(m_nIcmp, 0, str);
	m_list_icmp.SetItemText(m_nIcmp, 1, g_DisplayIcmp.type);
	m_list_icmp.SetItemText(m_nIcmp, 2, g_DisplayIcmp.code);
	m_list_icmp.SetItemText(m_nIcmp, 3, g_DisplayIcmp.checksum);
	m_list_icmp.SetItemText(m_nIcmp, 4, g_DisplayIcmp.information);
	UpdateData(FALSE);
	PacketNumber.icmp = m_nIcmp+1;
	m_nIcmp++;  
	return  0;
}
LRESULT CProtocolAnalysisDlg::OnTcp(WPARAM wParam, LPARAM lParam)
{
	RAW_PACKET *pRawPacket = (RAW_PACKET *)lParam;
	pRawPacket->tcpOrUdp_seq= m_nTcp;
	char str[10]; 
	sprintf(str, "%d", m_nTcp);
	m_list_tcp.InsertItem(m_nTcp,str);
	/*添加附加据,即数将列表项与存放原始数据包的堆地址指针关联*/
	m_list_tcp.SetItemData(m_nTcp,(DWORD)lParam);
	m_list_tcp.SetItemText(m_nTcp, 0, str);
	m_list_tcp.SetItemText(m_nTcp, 1, g_DisplayTCP.SrcPort);
	m_list_tcp.SetItemText(m_nTcp, 2, g_DisplayTCP.DstPort);
	m_list_tcp.SetItemText(m_nTcp, 3, g_DisplayTCP.SequenceNum);
	m_list_tcp.SetItemText(m_nTcp, 4, g_DisplayTCP.Acknowledgment);
	m_list_tcp.SetItemText(m_nTcp, 5, g_DisplayTCP.HdrLen);
	m_list_tcp.SetItemText(m_nTcp, 6, g_DisplayTCP.Zero);
	m_list_tcp.SetItemText(m_nTcp, 7, g_DisplayTCP.Flags);
	m_list_tcp.SetItemText(m_nTcp, 8, g_DisplayTCP.AdvertisedWindow);
	m_list_tcp.SetItemText(m_nTcp, 9, g_DisplayTCP.Checksum);
	m_list_tcp.SetItemText(m_nTcp, 10, g_DisplayTCP.UrgPtr);
	UpdateData(FALSE);
	PacketNumber.tcp = m_nTcp+1;
	m_nTcp++; 
	return  0;
}
LRESULT CProtocolAnalysisDlg::OnHttp(WPARAM wParam, LPARAM lParam)
{
	char str[10]; 
	sprintf(str, "%d", m_nHttp);
	m_list_http.InsertItem(m_nHttp,str);
	/*添加附加据,即数将列表项与存放原始数据包的堆地址指针关联*/
	m_list_http.SetItemData(m_nHttp,(DWORD)lParam);
	m_list_http.SetItemText(m_nHttp, 0, str);
	/////////////////
	RAW_PACKET* pRawPacket = (RAW_PACKET*)lParam;
	MAC_HEADER* pMacHdr = (MAC_HEADER*)pRawPacket->pPktData;
	if (ntohs(pMacHdr->LengthOrType) > 1500)
	{
		struct IPV4 *pIPHdr = (struct IPV4 *)((BYTE*)pMacHdr+sizeof(MAC_HEADER));
		in_addr ipAddr;
		//ip源地址
		ipAddr.s_addr = pIPHdr->SourceAddr;
		m_list_http.SetItemText(m_nHttp, 1, inet_ntoa(ipAddr));
		//IP目的地址
		ipAddr.s_addr = pIPHdr->DestinationAddr;
		m_list_http.SetItemText(m_nHttp, 2, inet_ntoa(ipAddr));
		int len = ntohs(pIPHdr->Length);//包含ip头和数据部分
		int off_IP_hdr =(int)wParam;
		BYTE *pHttp=(BYTE *)pIPHdr+off_IP_hdr;//定位到http开头处
		if (len <= 40)//ip包长度校验
		{
			return -1;
		}
		else
		{
	     	//解析HTTP报文---------------------------------------------------------
			int n = 0;
			char buffer[BUFFER_MAX_LENGTH];
			int bufsize = 0;
			for( ;n+off_IP_hdr < len; n++)//http相对于ip的偏移量是否小于ip长
			{
				buffer[bufsize] = *(pHttp+n); /* 复制httt内容到buffer */
				bufsize ++;
			}
			buffer[bufsize] = '\0';
			m_list_http.SetItemText(m_nHttp, 3, buffer);
		    //解析HTTP报文结束-----------------------------------------------------
		}//else
	}//if
	UpdateData(FALSE);
	PacketNumber.http = m_nHttp+1;
	m_nHttp++; 
	return  0;
}
LRESULT CProtocolAnalysisDlg::OnUdp(WPARAM wParam, LPARAM lParam)
{
	RAW_PACKET *pRawPacket = (RAW_PACKET *)lParam;
	pRawPacket->tcpOrUdp_seq= m_nUdp;
	char str[10]; 
	sprintf(str, "%d", m_nUdp);
	m_list_udp.InsertItem(m_nUdp,str);
	/*添加附加据,即数将列表项与存放原始数据包的堆地址指针关联*/
	m_list_udp.SetItemData(m_nUdp,(DWORD)lParam);
	m_list_udp.SetItemText(m_nUdp, 0, str);
	m_list_udp.SetItemText(m_nUdp, 1, g_DisplayUDP.SrcPort);
	m_list_udp.SetItemText(m_nUdp, 2, g_DisplayUDP.DstPort);
	m_list_udp.SetItemText(m_nUdp, 3, g_DisplayUDP.Length);
	m_list_udp.SetItemText(m_nUdp, 4, g_DisplayUDP.Checksum);
	UpdateData(FALSE);
	PacketNumber.udp = m_nUdp+1;
	m_nUdp++;  
	return  0;
}
LRESULT CProtocolAnalysisDlg::OnDns(WPARAM wParam, LPARAM lParam)
{
	RAW_PACKET *pRawPacket = (RAW_PACKET *)lParam;
	char str[MAX]; 
	sprintf(str, "%d", m_nDns);
	struct IPV4 *pIPHdr = (struct IPV4 *)(pRawPacket->pPktData+sizeof(MAC_HEADER));
	struct DNS *pDns =(struct DNS *)((BYTE*)pIPHdr+pIPHdr->HeaderLength*4+
		sizeof(struct UDP));
	m_list_Dns.InsertItem(m_nDns,str);
	/*添加附加据,即数将列表项与存放原始数据包的堆地址指针关联*/
	m_list_Dns.SetItemData(m_nDns,(DWORD)lParam);
	m_list_Dns.SetItemText(m_nDns, 0, str);
	sprintf(str, "%d",ntohs(pDns->d_id));
	m_list_Dns.SetItemText(m_nDns, 1,str);
	/*
	标志(2个字节)：QR opcode AA TC RD RA zero rcode .
	QR(1比特）opcode（4比特） AA（1比特） TC（1比特） 
	RD(1比特)RA（1比特） zero（3比特） rcode（4比特）
	*/
	unsigned short flag= ntohs(pDns->d_option);
    int ival=flag&0x8000;
	sprintf(str,"%s ",ival ? _T("响应"):_T("查询"));
	m_list_Dns.SetItemText(m_nDns, 2,str);
	ival=flag&0x7800;
	switch (ival)
	{
	case 0:
			sprintf(str,"%s ",_T("标准"));
		break;
		case 1:
			sprintf(str,"%s ",_T("反向"));
		break;
		case 2:
			sprintf(str,"%s ",_T("服务器状态请求"));
		break;
		default:
			sprintf(str,"%s ",_T("--"));
	}
	m_list_Dns.SetItemText(m_nDns, 3,str);
	ival=flag&0x0400;
	sprintf(str,"%s ",ival ? _T("权限服务器"):_T("--"));
	m_list_Dns.SetItemText(m_nDns, 4,str);
	ival=flag&0x0200;
	sprintf(str,"%s ",ival ? _T("截断(>512)"):_T("--"));
	m_list_Dns.SetItemText(m_nDns, 5,str);
	ival=flag&0x0100;
	sprintf(str,"%s ",ival ? _T("期望递归"):_T("--"));
	m_list_Dns.SetItemText(m_nDns, 6,str);
	ival=flag&0x0080;
	sprintf(str,"%s ",ival ? _T("支持递归"):_T("--"));
	m_list_Dns.SetItemText(m_nDns, 7,str);
	m_list_Dns.SetItemText(m_nDns, 8,_T("0"));
	ival=flag&0x000F;
	switch (ival)
	{
		case 0:
			sprintf(str,"%s ",_T("没有错误"));
		break;
		case 1:
			sprintf(str,"%s ",_T("报文格式错误"));
		break;
		case 2:
			sprintf(str,"%s ",_T("服务器失败"));
		break;
		case 3:
			sprintf(str,"%s ",_T("名字错误"));
		break;
		case 4:
			sprintf(str,"%s ",_T("查询类型不支持"));
		break;
		case 5:
			sprintf(str,"%s ",_T("拒绝"));
		break;	
		default:
			sprintf(str,"%s ",_T("--"));//6-15保留
	}
	m_list_Dns.SetItemText(m_nDns, 9,str);
	sprintf(str, "%d",ntohs(pDns->d_qdcount));
	m_list_Dns.SetItemText(m_nDns, 10, str);
	sprintf(str, "%d",ntohs(pDns->d_ancount));
	m_list_Dns.SetItemText(m_nDns, 11, str);
	sprintf(str, "%d",ntohs(pDns->d_nscount));
	m_list_Dns.SetItemText(m_nDns, 12,str);
	sprintf(str, "%d",ntohs(pDns->d_arcount));
	m_list_Dns.SetItemText(m_nDns, 13,str);
	UpdateData(FALSE);
	PacketNumber.dns = m_nDns+1;
	m_nDns++; 
	return  0;
}

void CProtocolAnalysisDlg::OnButtonStart()
{
	MessageBeep(MB_OK);
	g_StopThread = FALSE;
	m_pThread = AfxBeginThread(ThreadPacketCapture, this);
	m_pThread->m_bAutoDelete = FALSE;
}
void CProtocolAnalysisDlg::OnButtonStop()
{
	if (g_StopThread == TRUE)
	{
		return;
	}
	g_StopThread = TRUE;
	CButton *p=(CButton*)GetDlgItem (IDC_BUTTON_END);
	p->EnableWindow (FALSE);
	CMenu *pp=(CMenu *)GetMenu();
	pp->EnableMenuItem (MENU_STOP,TRUE);
	CButton *p2=(CButton*)GetDlgItem (IDC_BUTTON_START);
	p2->EnableWindow (TRUE);
	CMenu *pp2=(CMenu *)GetMenu();
	pp2->EnableMenuItem (MENU_START,FALSE);
}


void CProtocolAnalysisDlg::OnSelchangeTab1(NMHDR* pNMHDR, LRESULT* pResult)
{
	if (m_tab1.GetCurSel() == 0)
	{
		m_list_common.ShowWindow(SW_SHOW);
		m_list_arp.ShowWindow(SW_HIDE);
		m_list_ip.ShowWindow(SW_HIDE);
		m_list_tcp.ShowWindow(SW_HIDE);
		m_list_udp.ShowWindow(SW_HIDE);
		m_list_icmp.ShowWindow(SW_HIDE);
		m_list_ethernet.ShowWindow(SW_HIDE);
		m_list_http.ShowWindow(SW_HIDE);
		m_list_Dns.ShowWindow(SW_HIDE);
		CStatic *p=(CStatic *)GetDlgItem(IDC_STATIC_STATUS);
		p->SetWindowText ("数据包信息");
		m_pCurrentList= &m_list_common;
	}
	else if(m_tab1.GetCurSel () == 1 )
	{
		m_list_ethernet.ShowWindow(SW_SHOW);
		m_list_icmp.ShowWindow(SW_HIDE);
		m_list_ip.ShowWindow(SW_HIDE);
		m_list_common.ShowWindow(SW_HIDE);
		m_list_arp.ShowWindow(SW_HIDE);
		m_list_udp.ShowWindow(SW_HIDE);
		m_list_tcp.ShowWindow(SW_HIDE);
		m_list_http.ShowWindow(SW_HIDE);
		m_list_Dns.ShowWindow(SW_HIDE);
		CStatic *p=(CStatic *)GetDlgItem(IDC_STATIC_STATUS);
		p->SetWindowText ("以太网协议分析");
		m_pCurrentList = &m_list_ethernet;
	}
	else if (m_tab1.GetCurSel() == 2)
	{
		m_list_arp.ShowWindow(SW_SHOW);
		m_list_common.ShowWindow(SW_HIDE);
		m_list_ip.ShowWindow(SW_HIDE);
		m_list_tcp.ShowWindow(SW_HIDE);
		m_list_udp.ShowWindow(SW_HIDE);
		m_list_icmp.ShowWindow(SW_HIDE);
		m_list_ethernet.ShowWindow(SW_HIDE);
		m_list_http.ShowWindow(SW_HIDE);
		m_list_Dns.ShowWindow(SW_HIDE);
		CStatic *p=(CStatic *)GetDlgItem(IDC_STATIC_STATUS);
		p->SetWindowText ("ARP协议分析");
		m_pCurrentList=&m_list_arp;
	}
	else if (m_tab1.GetCurSel() == 3)
	{
		m_list_ip.ShowWindow(SW_SHOW);
		m_list_common.ShowWindow(SW_HIDE);
		m_list_arp.ShowWindow(SW_HIDE);
		m_list_tcp.ShowWindow(SW_HIDE);
		m_list_udp.ShowWindow(SW_HIDE);
		m_list_icmp.ShowWindow(SW_HIDE);
		m_list_ethernet.ShowWindow(SW_HIDE);
		m_list_http.ShowWindow(SW_HIDE);
		m_list_Dns.ShowWindow(SW_HIDE);
		CStatic *p=(CStatic *)GetDlgItem(IDC_STATIC_STATUS);
		p->SetWindowText ("IP协议分析");
		m_pCurrentList = &m_list_ip;
	}
	else if (m_tab1.GetCurSel() == 4)
	{
		m_list_icmp.ShowWindow(SW_SHOW);
		m_list_ip.ShowWindow(SW_HIDE);
		m_list_common.ShowWindow(SW_HIDE);
		m_list_arp.ShowWindow(SW_HIDE);
		m_list_udp.ShowWindow(SW_HIDE);
		m_list_tcp.ShowWindow(SW_HIDE);
		m_list_ethernet.ShowWindow(SW_HIDE);
		m_list_http.ShowWindow(SW_HIDE);
		m_list_Dns.ShowWindow(SW_HIDE);
		CStatic *p=(CStatic *)GetDlgItem(IDC_STATIC_STATUS);
		p->SetWindowText ("ICMP协议分析");
		m_pCurrentList = & m_list_icmp;
	}
	else if (m_tab1.GetCurSel() == 5)
	{
		m_list_tcp.ShowWindow(SW_SHOW);
		m_list_ip.ShowWindow(SW_HIDE);
		m_list_common.ShowWindow(SW_HIDE);
		m_list_arp.ShowWindow(SW_HIDE);
		m_list_udp.ShowWindow(SW_HIDE);
		m_list_icmp.ShowWindow(SW_HIDE);
		m_list_ethernet.ShowWindow(SW_HIDE);
		m_list_http.ShowWindow(SW_HIDE);
		m_list_Dns.ShowWindow(SW_HIDE);
		CStatic *p=(CStatic *)GetDlgItem(IDC_STATIC_STATUS);
		p->SetWindowText ("TCP协议分析");
		m_pCurrentList =&m_list_tcp;
	}
	else if (m_tab1.GetCurSel() == 6)
	{
		m_list_udp.ShowWindow(SW_SHOW);
		m_list_ip.ShowWindow(SW_HIDE);
		m_list_common.ShowWindow(SW_HIDE);
		m_list_arp.ShowWindow(SW_HIDE);
		m_list_icmp.ShowWindow(SW_HIDE);
		m_list_tcp.ShowWindow(SW_HIDE);
		m_list_ethernet.ShowWindow(SW_HIDE);
		m_list_http.ShowWindow(SW_HIDE);
		m_list_Dns.ShowWindow(SW_HIDE);
		CStatic *p=(CStatic *)GetDlgItem(IDC_STATIC_STATUS);
		p->SetWindowText ("UDP协议分析");
		m_pCurrentList = &m_list_udp;
	}
	else if (m_tab1.GetCurSel() == 7)
	{
		m_list_http.ShowWindow(SW_SHOW);
		m_list_common.ShowWindow(SW_HIDE);
		m_list_arp.ShowWindow(SW_HIDE);
		m_list_ip.ShowWindow(SW_HIDE);
		m_list_tcp.ShowWindow(SW_HIDE);
		m_list_udp.ShowWindow(SW_HIDE);
		m_list_icmp.ShowWindow(SW_HIDE);
		m_list_ethernet.ShowWindow(SW_HIDE);
		m_list_Dns.ShowWindow(SW_HIDE);
		CStatic *p=(CStatic *)GetDlgItem(IDC_STATIC_STATUS);
		p->SetWindowText ("HTTP协议分析");
		m_pCurrentList = & m_list_http;
	}
	else
	{
		m_list_Dns.ShowWindow(SW_SHOW);
		m_list_common.ShowWindow(SW_HIDE);
		m_list_arp.ShowWindow(SW_HIDE);
		m_list_ip.ShowWindow(SW_HIDE);
		m_list_tcp.ShowWindow(SW_HIDE);
		m_list_udp.ShowWindow(SW_HIDE);
		m_list_icmp.ShowWindow(SW_HIDE);
		m_list_ethernet.ShowWindow(SW_HIDE);
		m_list_http.ShowWindow(SW_HIDE);
		CStatic *p=(CStatic *)GetDlgItem(IDC_STATIC_STATUS);
		p->SetWindowText ("DNS协议分析");
		m_pCurrentList = &m_list_Dns;
	}
	CRect rect1, rect2;
		m_tab1.GetWindowRect(rect1);// 屏幕坐标  
		m_tab1.GetItemRect(0, rect2);// 取得Tab上方按钮的大小 
		ScreenToClient(rect1);//转换为屏幕坐标
		rect1.left += 2;
		rect1.top += rect2.Height() + 3;
		int h=(rect1.Height() - rect2.Height())/2-2;
		m_list_common.SetWindowPos(NULL, rect1.left, rect1.top, rect1.Width(),
		h	 , NULL); 
		m_list_ethernet.SetWindowPos(NULL, rect1.left, rect1.top, rect1.Width(),
			h, NULL); 
		m_list_arp.SetWindowPos(NULL, rect1.left, rect1.top, rect1.Width(),
			h , NULL); 
		m_list_ip.SetWindowPos(NULL, rect1.left, rect1.top, rect1.Width(),
			h, NULL); 
		m_list_tcp.SetWindowPos(NULL, rect1.left, rect1.top, rect1.Width(),
			h, NULL); 
		m_list_udp.SetWindowPos(NULL, rect1.left, rect1.top, rect1.Width(),
			h, NULL); 
		m_list_icmp.SetWindowPos(NULL, rect1.left, rect1.top, rect1.Width(),
			h, NULL); 
		m_list_http.SetWindowPos(NULL, rect1.left, rect1.top, rect1.Width(),
			h, NULL); 
		m_list_Dns.SetWindowPos(NULL, rect1.left, rect1.top, rect1.Width(),
			h, NULL); 
		m_tree.SetWindowPos(NULL, rect1.left,rect2.bottom+h+26, rect1.Width()/2,
			h+6, NULL); 
		m_tree.ShowWindow(SW_SHOW);
		m_EditCtrl.SetWindowPos(NULL, rect1.left+rect1.Width()/2 +3,rect2.bottom+h+26 , rect1.Width()/2,
			h+6, NULL); 
		m_EditCtrl.ShowWindow(SW_SHOW);
	*pResult = 0;
}
/*开始菜单*/
void CProtocolAnalysisDlg::OnStart()
{
	g_StopThread = FALSE;
	g_hWnd = GetSafeHwnd();
	m_pThread = AfxBeginThread(ThreadPacketCapture, g_hWnd);
	m_pThread->m_bAutoDelete = FALSE;
}
void CProtocolAnalysisDlg::OnStop()
{
	if (g_StopThread == TRUE)
	{
		return;
	}
	g_StopThread = TRUE;
	CButton *p=(CButton*)GetDlgItem (IDC_BUTTON_END);
	p->EnableWindow (FALSE);
	CMenu *pp=(CMenu *)GetMenu();
	pp->EnableMenuItem (MENU_STOP,TRUE);
	CButton *p2=(CButton*)GetDlgItem (IDC_BUTTON_START);
	p2->EnableWindow (TRUE);
	CMenu *pp2=(CMenu *)GetMenu();
	pp2->EnableMenuItem (MENU_START,FALSE);
}

void CProtocolAnalysisDlg::OnExit()
{
	int result =MessageBox(" \n\n你真的要退出吗？","网络协议分析系统",MB_OKCANCEL);
	if(result==IDOK)
	{
		ReleaseAll();
		PostQuitMessage(1);
	}
}

void CProtocolAnalysisDlg::OnSetFileter()
{
	Cfilterdlg dlg;
	int result = dlg.DoModal();
	if (result == IDOK)
	{
		strcpy(g_PacketFilter, dlg.m_filter);
	}
}
void CProtocolAnalysisDlg::OnDrawItem(int nIDCtl, LPDRAWITEMSTRUCT lpDrawItemStruct)
{
	CDialog::OnDrawItem(nIDCtl, lpDrawItemStruct);
}

void CProtocolAnalysisDlg::OnMeasureItem(int nIDCtl,
										 LPMEASUREITEMSTRUCT lpMeasureItemStruct)
{
	CDialog::OnMeasureItem(nIDCtl, lpMeasureItemStruct);
}

void CProtocolAnalysisDlg::OnRButtonUp(UINT nFlags, CPoint point)
{
	CDialog::OnRButtonUp(nFlags, point);
}

LRESULT CProtocolAnalysisDlg::DefWindowProc(UINT message, WPARAM wParam, LPARAM lParam)
{
	// TODO: Add your specialized code here and/or call the base class
	LRESULT lrst = CDialog::DefWindowProc(message, wParam, lParam);
	if (!::IsWindow(m_hWnd))
		return lrst;
	if (message == WM_MOVE ||
		message == WM_PAINT ||
		message == WM_NCPAINT ||
		message == WM_NCACTIVATE ||
		message == WM_NOTIFY)
	{
		CDC* pWinDC = GetWindowDC();
		if (pWinDC)
			DrawTitleBar(pWinDC);
		ReleaseDC(pWinDC);
	}
	return lrst;
}

void CProtocolAnalysisDlg::DrawTitleBar(CDC* pDC)
{
	if (m_hWnd)
	{
		CBitmap* pBitmap = new CBitmap;
		CBitmap* pOldBitmap;
		CDC* pDisplayMemDC = new CDC;
		pDisplayMemDC->CreateCompatibleDC(pDC);
		pBitmap->LoadBitmap(IDB_BITMAP8);
		pOldBitmap = (CBitmap *) pDisplayMemDC->SelectObject(pBitmap);
		pDC->BitBlt(300, 5, 500, 100, pDisplayMemDC, 0, 0, SRCCOPY);
		pDisplayMemDC->SelectObject(pOldBitmap);
		pBitmap->DeleteObject();
		CRect rtWnd, rtTitle, rtButtons;
		GetWindowRect(&rtWnd); 
		rtTitle.left = GetSystemMetrics(SM_CXFRAME);
		rtTitle.top = GetSystemMetrics(SM_CYFRAME);
		rtTitle.right = rtWnd.right -
			rtWnd.left -
			GetSystemMetrics(SM_CXFRAME);
		rtTitle.bottom = rtTitle.top + GetSystemMetrics(SM_CYSIZE);
		CPoint point;
		CBrush Brush(0x551A8B);
		CBrush* pOldBrush = pDC->SelectObject(&Brush);
		point.x = rtWnd.Width(); 
		point.y = GetSystemMetrics(SM_CYFRAME) + 1;
		pDC->PatBlt(0, rtWnd.Height() - point.y, point.x, point.y, PATCOPY);
		CBrush Brush2(0x00CD00);
		pOldBrush = pDC->SelectObject(&Brush2);
		pDC->PatBlt(0, rtWnd.Height() - 3, rtWnd.Width(), 1, PATCOPY);
		
		ReleaseDC(pDisplayMemDC);
		delete pDisplayMemDC;
		delete pBitmap;
	}
}
void CProtocolAnalysisDlg::OnLButtonDown(UINT nFlags, CPoint point)
{
	CDialog::OnLButtonDown(nFlags, point);
}

void CProtocolAnalysisDlg::OnMouseMove(UINT nFlags, CPoint point)
{
	CDialog::OnMouseMove(nFlags, point);
}

void CProtocolAnalysisDlg::OnLButtonUp(UINT nFlags, CPoint point)
{
	CDialog::OnLButtonUp(nFlags, point);
}

void CProtocolAnalysisDlg::OnSize(UINT nType, int cx, int cy)
{
	CDialog::OnSize(nType, cx, cy);
	CRect rect;
	GetClientRect(&rect);//取得客户区的大小 
	static int i=0;
	if(i==1)
	{
		CRect newrect(rect);
		newrect.top =rect.top +30;
		m_tab1.MoveWindow (newrect);
		CRect rect1, rect2;
		m_tab1.GetWindowRect(rect1);// 屏幕坐标  
		m_tab1.GetItemRect(0, rect2);// 取得Tab上方按钮的大小 
		ScreenToClient(rect1);//转换为屏幕坐标
		rect1.left += 2;
		rect1.top += rect2.Height() + 3;
		int h=(rect1.Height() - rect2.Height())/2-6;
		m_picCtrl.SetWindowPos(NULL, rect1.right-60, rect1.top-50,30,
		 30, NULL);
		m_picCtrl.ShowWindow(SW_SHOW);
		m_list_common.SetWindowPos(NULL, rect1.left, rect1.top, rect1.Width(),
		h	 , NULL); 
		m_list_ethernet.SetWindowPos(NULL, rect1.left, rect1.top, rect1.Width(),
			h, NULL);
		m_list_arp.SetWindowPos(NULL, rect1.left, rect1.top, rect1.Width(),
			h , NULL); 
		m_list_ip.SetWindowPos(NULL, rect1.left, rect1.top, rect1.Width(),
			h, NULL); 
		m_list_tcp.SetWindowPos(NULL, rect1.left, rect1.top, rect1.Width(),
			h, NULL); 
		m_list_udp.SetWindowPos(NULL, rect1.left, rect1.top, rect1.Width(),
			h, NULL); 
		m_list_icmp.SetWindowPos(NULL, rect1.left, rect1.top, rect1.Width(),
			h, NULL); 
		m_list_http.SetWindowPos(NULL, rect1.left, rect1.top, rect1.Width(),
			h, NULL);
		m_list_Dns.SetWindowPos(NULL, rect1.left, rect1.top, rect1.Width(),
			h, NULL);
		m_tree.SetWindowPos(NULL, rect1.left,rect2.bottom+h+30, rect1.Width()/2,
			h+16, NULL); 
		m_tree.ShowWindow(SW_SHOW);
		m_EditCtrl.SetWindowPos(NULL, rect1.left+rect1.Width()/2 +3,rect2.bottom+h+30 , rect1.Width()/2,
			h+16, NULL); 
		m_EditCtrl.ShowWindow(SW_SHOW);
	}
	i++;
	if(i==2)
		i=1;
	InvalidateRect(rect);//重绘
	GetWindowRect(&rect);
	InvalidateRect(rect);	
}
void CProtocolAnalysisDlg::OnClickTab1(NMHDR* pNMHDR, LRESULT* pResult)
{
		CRect rect1, rect2;
		m_tab1.GetWindowRect(rect1);// 屏幕坐标  
		m_tab1.GetItemRect(0, rect2);// 取得Tab上方按钮的大小 
		ScreenToClient(rect1);//转换为屏幕坐标
		rect1.left += 2;
		rect1.top += rect2.Height() + 3;
		int h=(rect1.Height() - rect2.Height())/2-2;
		m_list_common.SetWindowPos(NULL, rect1.left, rect1.top, rect1.Width(),
		h	 , NULL); 
		m_list_arp.SetWindowPos(NULL, rect1.left, rect1.top, rect1.Width(),
			h , NULL); 
		m_list_ip.SetWindowPos(NULL, rect1.left, rect1.top, rect1.Width(),
			h, NULL); 
		m_list_tcp.SetWindowPos(NULL, rect1.left, rect1.top, rect1.Width(),
			h, NULL); 
		m_list_udp.SetWindowPos(NULL, rect1.left, rect1.top, rect1.Width(),
			h, NULL); 
		m_list_icmp.SetWindowPos(NULL, rect1.left, rect1.top, rect1.Width(),
			h, NULL); 
		m_list_ethernet.SetWindowPos(NULL, rect1.left, rect1.top, rect1.Width(),
			h, NULL); 
		m_list_http.SetWindowPos(NULL, rect1.left, rect1.top, rect1.Width(),
			h, NULL);
		m_list_Dns.SetWindowPos(NULL, rect1.left, rect1.top, rect1.Width(),
			h, NULL);
		m_tree.SetWindowPos(NULL, rect1.left,rect2.bottom+h+28, rect1.Width()/2,
			h+6, NULL); 
		m_tree.ShowWindow(SW_SHOW);
		m_EditCtrl.SetWindowPos(NULL, rect1.left+rect1.Width()/2 +3,rect2.bottom+h+28 , rect1.Width()/2,
			h+6, NULL); 
		m_EditCtrl.ShowWindow(SW_SHOW);
		//切换tab时清除树和列表信息
		m_tree.DeleteAllItems();
		m_EditCtrl.SetWindowText(_T(""));
	*pResult = 0;
}
void CProtocolAnalysisDlg::OnMenuhelp() 
{
	Chelpdialog dia;
	dia.DoModal();
}
void CProtocolAnalysisDlg::OnMenuOpenDumpFile() 
{
	g_StopThread = FALSE;
	g_hWnd = GetSafeHwnd();
	m_pThread = AfxBeginThread(ThreadReadFile, g_hWnd);
	m_pThread->m_bAutoDelete = FALSE;
}
void CProtocolAnalysisDlg::OnButtonOpenDumpFile() 
{
	g_StopThread = FALSE;
	g_hWnd = GetSafeHwnd();
	m_pThread = AfxBeginThread(ThreadReadFile, g_hWnd);
	m_pThread->m_bAutoDelete = FALSE;
}
void CProtocolAnalysisDlg::OnButtonSetFilter() 
{
	Cfilterdlg dlg;
	int result = dlg.DoModal();
	if (result == IDOK)
	{
		strcpy(g_PacketFilter, dlg.m_filter);
	}
}

void CProtocolAnalysisDlg::OnSave() 
{
	// TODO: Add your command handler code here
	//构造保存对话框类
	LPCTSTR szTypes =_T("tcpdump Files (*.pcap)|*.pcap|")
		_T("libpcap Files (*.cap)|*.cap|")
		_T("All Files (*.*)|*.*||");
	CFileDialog *pDlg = new CFileDialog( FALSE, _T(".pcap"), NULL, OFN_HIDEREADONLY |
		OFN_OVERWRITEPROMPT |OFN_ALLOWMULTISELECT|OFN_ENABLESIZING, szTypes );
	//导出到的文件名及路径
	if(IDOK!=pDlg->DoModal())
	{
		return ;
	}
	m_strfileNamePath=pDlg->GetPathName();//得到文件名及路径
	delete pDlg;
	if(m_SaveDumpFile)//是否保存文件
	{
		//拷贝到要导出的目录中,注意MoveFile不可,文件属性问题
		::CopyFile((LPCTSTR)(m_strFilePath+_T("\\temp.pcap")),(LPCTSTR)m_strfileNamePath,0);
	}
	else
	{
		MessageBox(_T("你没在系统设置里选择保存文件！"),_T("请选择保存文件."),MB_DEFBUTTON1);
	}
}

int CProtocolAnalysisDlg::OnCreate(LPCREATESTRUCT lpCreateStruct) 
{
	if (CDialog::OnCreate(lpCreateStruct) == -1)
		return -1;
	
	// TODO: Add your specialized creation code here
	
	return 0;
}

void CProtocolAnalysisDlg::OnCancelMode() 
{
	CDialog::OnCancelMode();
	
	// TODO: Add your message handler code here
	
}

//在显示捕获信息
void CProtocolAnalysisDlg::ShowPacketInfo(RAW_PACKET* pRawPacket)
{
	CString strPktData=_T("") ;
	if (pRawPacket)
	{

		CString strLineHex=_T(""), strLineAscii=_T("");
		CString strTmp=_T(""); 
		UCHAR cTmp;	
		for (UINT i=0; i<pRawPacket->PktHeader.caplen; i++)
		{
			//插入行号
			if (i%16 == 0)
			{
				strTmp.Format("%04X ", i);//十六进制输出,字段宽度4,空格
				strPktData += strTmp;
				strLineHex.Empty();
				strLineAscii.Empty();
			}
			//插入数据
			cTmp = *(pRawPacket->pPktData+i);
			strTmp.Format("%02X ", cTmp);
			strLineHex += strTmp;
			if (isprint(cTmp))
				strLineAscii += cTmp;
			else
				strLineAscii += '.';

			//插入回车换行
			if (i%16 == 15)
			{
				strPktData += strLineHex;
				strPktData += strLineAscii;
				strPktData += "\r\n";
			}
		}
		//如果最后一行不够16个字符则单独处理
		if (--i%16 != 15)
		{
			for (UINT j=0; j<15-i%16; j++)
			{
				strLineHex += "   ";
				strLineAscii += ' ';
			}
			strPktData += strLineHex;
			strPktData += strLineAscii;
		}
	}
	//在编辑视图中显示
	m_EditCtrl.SetWindowText(strPktData);
	//树控件 只显示MAC
	//先清除全部树
	m_tree.DeleteAllItems();
	UpdateWindow();
	if (pRawPacket == NULL)
		return ;
	CString strItem;
	//加入根节点
	strItem.Format("Frame (%d bytes)", pRawPacket->PktHeader.len);
	m_TreeRoot=m_tree.InsertItem(strItem,0,0,TVI_ROOT,TVI_LAST);
	//加入一级子节点Mac头部
	MAC_HEADER* pMacHdr = (MAC_HEADER*)pRawPacket->pPktData;
	//检查以太帧类型,别忘了字节序转化
	if (ntohs(pMacHdr->LengthOrType)> 1500)//类型字段(Ethernet II)
		strItem.Format("MAC header (Ethernet II)");
	else							
		strItem.Format("MAC header (IEEE 802.3)");
	m_MacHdrRoot = m_tree.InsertItem(strItem, 1,1,m_TreeRoot,TVI_LAST);
	//解析Mac帧--------------------------------------------------------
	//Mac头部子节点：Mac目的地址
	strItem.Format("目的Mac: %02X:%02X:%02X:%02X:%02X:%02X",
					pMacHdr->DesMacAddr[0],
					pMacHdr->DesMacAddr[1],
					pMacHdr->DesMacAddr[2],
					pMacHdr->DesMacAddr[3],
					pMacHdr->DesMacAddr[4],
					pMacHdr->DesMacAddr[5]);
	m_tree.InsertItem(strItem, 3,3,m_MacHdrRoot,TVI_LAST);

	//Mac头部子节点：Mac源地址
	strItem.Format("源Mac: %02X:%02X:%02X:%02X:%02X:%02X", 
					pMacHdr->SrcMacAddr[0],
					pMacHdr->SrcMacAddr[1],
					pMacHdr->SrcMacAddr[2],
					pMacHdr->SrcMacAddr[3],
					pMacHdr->SrcMacAddr[4],
					pMacHdr->SrcMacAddr[5]);
	m_tree.InsertItem(strItem, 3,3,m_MacHdrRoot,TVI_LAST);
	m_tree.Expand(m_TreeRoot,TVE_EXPAND);
}
void CProtocolAnalysisDlg::ShowIpInfo(int nItem)
{
	m_tree.InsertItem(_T("协议类型：IP"), 5,5,m_MacHdrRoot,TVI_LAST);
	//处理下ipv4 头部
	CString strItem;
	m_IpHdrRoot=m_tree.InsertItem(_T("IPV4"), 1,1,m_TreeRoot,TVI_LAST);
	strItem.Format("协议版本: %s",m_list_ip.GetItemText(nItem,1));//取得版本号
	m_tree.InsertItem(strItem, 4,4,m_IpHdrRoot,TVI_LAST);
	strItem.Format("首部长度: %s",m_list_ip.GetItemText(nItem,2));//取得首部长度
	m_tree.InsertItem(strItem, 6,6,m_IpHdrRoot,TVI_LAST);
	strItem.Format("服务质量: %s",m_list_ip.GetItemText(nItem,3));//取得服务质量
	m_tree.InsertItem(strItem, 7,7,m_IpHdrRoot,TVI_LAST);
	strItem.Format("Ip长度: %s",m_list_ip.GetItemText(nItem,4));//取得ip总长度
	m_tree.InsertItem(strItem, 6,6,m_IpHdrRoot,TVI_LAST);
	strItem.Format("标识: %s",m_list_ip.GetItemText(nItem,5));//取得标识
	m_tree.InsertItem(strItem, 9,9,m_IpHdrRoot,TVI_LAST);
	strItem.Format("标志: %s",m_list_ip.GetItemText(nItem,6));//取得标志
	m_tree.InsertItem(strItem, 9,9,m_IpHdrRoot,TVI_LAST);
	strItem.Format("偏移量: %s",m_list_ip.GetItemText(nItem,7));//取得偏移量
	m_tree.InsertItem(strItem, 9,9,m_IpHdrRoot,TVI_LAST);
	strItem.Format("生存周期: %s",m_list_ip.GetItemText(nItem,8));//取得生存周期
	m_tree.InsertItem(strItem, 8,8,m_IpHdrRoot,TVI_LAST);
	strItem.Format("协议类型: %s",m_list_ip.GetItemText(nItem,9));//取得服协议类型
	m_tree.InsertItem(strItem, 5,5,m_IpHdrRoot,TVI_LAST);
	strItem.Format("校验和: %s",m_list_ip.GetItemText(nItem,10));//校验和
	m_tree.InsertItem(strItem, 2,2,m_IpHdrRoot,TVI_LAST);
	strItem.Format("源Ip: %s",m_list_ip.GetItemText(nItem,11));//取得源ip
	m_tree.InsertItem(strItem,3,3,m_IpHdrRoot,TVI_LAST);
	strItem.Format("目的Ip: %s",m_list_ip.GetItemText(nItem,12));//取得目的Ip
	m_tree.InsertItem(strItem, 3,3,m_IpHdrRoot,TVI_LAST);
}

void CProtocolAnalysisDlg::ShowUdpInfo(int nItem)
{
	CString strItem;
	m_UdpHdrRoot=m_tree.InsertItem(_T("UDP "), 1,1,m_TreeRoot,TVI_LAST);
	strItem.Format("源端口: %s",m_list_udp.GetItemText(nItem,1));//取得源端口
	m_tree.InsertItem(strItem, 3,3,m_UdpHdrRoot,TVI_LAST);
	strItem.Format("目的端口: %s",m_list_udp.GetItemText(nItem,2));//取得目的端口
	m_tree.InsertItem(strItem, 3,3,m_UdpHdrRoot,TVI_LAST);
	strItem.Format("长度: %s",m_list_udp.GetItemText(nItem,3));//取得Udp长度
	m_tree.InsertItem(strItem, 6,6,m_UdpHdrRoot,TVI_LAST);
	strItem.Format("校验和: %s",m_list_udp.GetItemText(nItem,4));//取得校验和
	m_tree.InsertItem(strItem, 2,2,m_UdpHdrRoot,TVI_LAST);
}

void CProtocolAnalysisDlg::ShowTcpInfo(int nItem)
{
	CString strItem;
	m_TcpHdrRoot=m_tree.InsertItem(_T("TCP "), 1,1,m_TreeRoot,TVI_LAST);
	strItem.Format("源端口: %s",m_list_tcp.GetItemText(nItem,1));//取得源端口
	m_tree.InsertItem(strItem, 3,3,m_TcpHdrRoot,TVI_LAST);
	strItem.Format("目的端口: %s",m_list_tcp.GetItemText(nItem,2));//取得目的端口
	m_tree.InsertItem(strItem, 3,3,m_TcpHdrRoot,TVI_LAST);
	strItem.Format("序列号: %s",m_list_tcp.GetItemText(nItem,3));//取得序列号
	m_tree.InsertItem(strItem, 9,9,m_TcpHdrRoot,TVI_LAST);
	strItem.Format("确认号: %s",m_list_tcp.GetItemText(nItem,4));//取得确认号
	m_tree.InsertItem(strItem, 9,9,m_TcpHdrRoot,TVI_LAST);
	strItem.Format("首部长度: %s",m_list_tcp.GetItemText(nItem,5));//取得首部长度
	m_tree.InsertItem(strItem, 6,6,m_TcpHdrRoot,TVI_LAST);
	strItem.Format("保留: %s",m_list_tcp.GetItemText(nItem,6));//取得保留
	m_tree.InsertItem(strItem, 7,7,m_TcpHdrRoot,TVI_LAST);
	strItem.Format("标志: %s",m_list_tcp.GetItemText(nItem,7));//取得确标志
	m_tree.InsertItem(strItem, 9,9,m_TcpHdrRoot,TVI_LAST);
	strItem.Format("窗口: %s",m_list_tcp.GetItemText(nItem,8));//取得确窗口
	m_tree.InsertItem(strItem, 5,5,m_TcpHdrRoot,TVI_LAST);
	strItem.Format("校验和: %s",m_list_tcp.GetItemText(nItem,9));//取得校验和
	m_tree.InsertItem(strItem, 2,2,m_TcpHdrRoot,TVI_LAST);
	strItem.Format("紧急指针: %s",m_list_tcp.GetItemText(nItem,10));//取得确认号
	m_tree.InsertItem(strItem, 10,10,m_TcpHdrRoot,TVI_LAST);
}
void CProtocolAnalysisDlg::ShowArpInfo(int nItem)
{
	CString strItem;
	m_ArpHdrRoot=m_tree.InsertItem(_T("ARP "), 1,1,m_TreeRoot,TVI_LAST);
	strItem.Format("硬件地址类型: %s",m_list_arp.GetItemText(nItem,1));//取得硬件地址类型
	m_tree.InsertItem(strItem, 5,5,m_ArpHdrRoot,TVI_LAST);
	strItem.Format("协议地址类型: %s",m_list_arp.GetItemText(nItem,2));//取得协议地址类型
	m_tree.InsertItem(strItem, 5,5,m_ArpHdrRoot,TVI_LAST);
	strItem.Format("硬件地址长度: %s",m_list_arp.GetItemText(nItem,3));//取得硬件地址长度
	m_tree.InsertItem(strItem, 6,6,m_ArpHdrRoot,TVI_LAST);
	strItem.Format("协议地址长度: %s",m_list_arp.GetItemText(nItem,4));//取得协议地址长度
	m_tree.InsertItem(strItem, 6,6,m_ArpHdrRoot,TVI_LAST);
	strItem.Format("Arp操作: %s",m_list_arp.GetItemText(nItem,5));//取得硬件地址长度
	m_tree.InsertItem(strItem, 7,7,m_ArpHdrRoot,TVI_LAST);
	HTREEITEM hItem=m_tree.GetChildItem(m_MacHdrRoot);//获取MAC第一个节点
	m_tree.InsertItem(m_tree.GetItemText(hItem), 3,3,m_ArpHdrRoot,TVI_LAST);//发送端MAC
	strItem.Format("发送端ip: %s",m_list_arp.GetItemText(nItem,7));//取得发送端ip
	m_tree.InsertItem(strItem, 3,3,m_ArpHdrRoot,TVI_LAST);
	m_tree.InsertItem(m_tree.GetItemText(m_tree.GetNextSiblingItem(hItem)),
		3,3,m_ArpHdrRoot,TVI_LAST);	//目的端MAC
	strItem.Format("目的端ip: %s",m_list_arp.GetItemText(nItem,8));//取得发送端ip
	m_tree.InsertItem(strItem, 3,3,m_ArpHdrRoot,TVI_LAST);
	strItem.Format("备注: %s",m_list_arp.GetItemText(nItem,6));//取得硬件地址长度
	m_tree.InsertItem(strItem, 9,9,m_ArpHdrRoot,TVI_LAST);
}
//Icmp
void CProtocolAnalysisDlg::ShowIcmpInfo(int nItem)
{
	CString strItem;
	m_IcmpHdrRoot=m_tree.InsertItem(_T("ICMP "), 1,1,m_TreeRoot,TVI_LAST);
	strItem.Format("类型: %s",m_list_icmp.GetItemText(nItem,1));//取得类型
	m_tree.InsertItem(strItem, 4,4,m_IcmpHdrRoot,TVI_LAST);
	strItem.Format("代码: %s",m_list_icmp.GetItemText(nItem,2));//取得代码
	m_tree.InsertItem(strItem, 9,9,m_IcmpHdrRoot,TVI_LAST);
	strItem.Format("校验和: %s",m_list_icmp.GetItemText(nItem,3));//取得校验和
	m_tree.InsertItem(strItem, 2,2,m_IcmpHdrRoot,TVI_LAST);
	strItem.Format("说明: %s",m_list_icmp.GetItemText(nItem,4));//取得说明
	m_tree.InsertItem(strItem, 9,9,m_IcmpHdrRoot,TVI_LAST);
}
//单击列表一栏
void CProtocolAnalysisDlg::OnClickListCom(NMHDR* pNMHDR, LRESULT* pResult) 
{
	// TODO: Add your control notification handler code here
	int nItem = m_list_common.GetNextItem( -1, LVNI_ALL | LVNI_SELECTED);
	if (nItem == -1)
		return ;
   //在静态文本中显示
	MessageBeep(65);
	RAW_PACKET* pRawPacket = (RAW_PACKET*)(m_list_common.GetItemData(nItem));
	ShowPacketInfo(pRawPacket);
	UpdateData(FALSE);	
	*pResult = 0;
}
void CProtocolAnalysisDlg::OnClickListEthernet(NMHDR* pNMHDR, LRESULT* pResult) 
{
	// TODO: Add your control notification handler code here
	int nItem = m_list_ethernet.GetNextItem( -1, LVNI_ALL | LVNI_SELECTED);
	if (nItem == -1)
		return ;
	MessageBeep(65);
	RAW_PACKET* pRawPacket = (RAW_PACKET*)(m_list_ethernet.GetItemData(nItem));
	ShowPacketInfo(pRawPacket);
	CString strItem;
	strItem.Format("协议类型: %s",m_list_ethernet.GetItemText(nItem,3));//取协议类型
	m_tree.InsertItem(strItem, 5,5,m_MacHdrRoot,TVI_LAST);
	*pResult = 0;
}

//Arp
void CProtocolAnalysisDlg::OnClickListArp(NMHDR* pNMHDR, LRESULT* pResult) 
{
	// TODO: Add your control notification handler code here
	int nItem = m_list_arp.GetNextItem( -1, LVNI_ALL | LVNI_SELECTED);
	if (nItem == -1)
		return ;
	MessageBeep(65);
	RAW_PACKET* pRawPacket = (RAW_PACKET*)(m_list_arp.GetItemData(nItem));
	ShowPacketInfo(pRawPacket);
	ShowArpInfo(nItem);
	UpdateData(FALSE);
	*pResult = 0;
}
//ip
void CProtocolAnalysisDlg::OnClickListIp(NMHDR* pNMHDR, LRESULT* pResult) 
{
	// TODO: Add your control notification handler code here
	int nItem = m_list_ip.GetNextItem( -1, LVNI_ALL | LVNI_SELECTED);
	if (nItem == -1)
		return ;
	MessageBeep(65);
	RAW_PACKET* pRawPacket = (RAW_PACKET*)(m_list_ip.GetItemData(nItem));
	ShowPacketInfo(pRawPacket);
	ShowIpInfo(pRawPacket->ip_seq);//根据其ip层的序号求其ip信息
	UpdateData(FALSE);
	*pResult = 0;
}
//icmp
void CProtocolAnalysisDlg::OnClickListIcmp(NMHDR* pNMHDR, LRESULT* pResult) 
{
	// TODO: Add your control notification handler code here
	int nItem = m_list_icmp.GetNextItem( -1, LVNI_ALL | LVNI_SELECTED);
	if (nItem == -1)
		return ;
	MessageBeep(65);
	RAW_PACKET* pRawPacket = (RAW_PACKET*)(m_list_icmp.GetItemData(nItem));
	ShowPacketInfo(pRawPacket);
	ShowIpInfo(pRawPacket->ip_seq);//根据其ip层的序号求其ip信息
	ShowIcmpInfo(nItem);
	UpdateData(FALSE);
	*pResult = 0;
}
//Tcp
void CProtocolAnalysisDlg::OnClickListTcp(NMHDR* pNMHDR, LRESULT* pResult) 
{
	// TODO: Add your control notification handler code here
	int nItem = m_list_tcp.GetNextItem( -1, LVNI_ALL | LVNI_SELECTED);
	if (nItem == -1)
		return ;
	MessageBeep(65);
	RAW_PACKET* pRawPacket = (RAW_PACKET*)(m_list_tcp.GetItemData(nItem));
	ShowPacketInfo(pRawPacket);
	ShowIpInfo(pRawPacket->ip_seq);//根据 其ip层的序号求其ip信息
	ShowTcpInfo(pRawPacket->tcpOrUdp_seq);//根据其传输层序号显示其 tcp信息
	UpdateData(FALSE);
	*pResult = 0;
}
//http
void CProtocolAnalysisDlg::OnClickListHttp(NMHDR* pNMHDR, LRESULT* pResult) 
{
	// TODO: Add your control notification handler code here
	int nItem = m_list_http.GetNextItem( -1, LVNI_ALL | LVNI_SELECTED);
	if (nItem == -1)
		return ;
	MessageBeep(65);
	RAW_PACKET* pRawPacket = (RAW_PACKET*)(m_list_http.GetItemData(nItem));
	ShowPacketInfo(pRawPacket);
	ShowIpInfo(pRawPacket->ip_seq);//根据其ip层的序号求其ip信息
	ShowTcpInfo(pRawPacket->tcpOrUdp_seq);//根据其传输层序号显示其 tcp信息
	//处理下http
	CString strItem;
	CString strTemp;
	HTREEITEM httpRoot=m_tree.InsertItem(_T("HTTP"), 1,1,m_TreeRoot,TVI_LAST);
	strItem.Format("%s",m_list_http.GetItemText(nItem,3));//取得http内容
	char buffer[BUFFER_MAX_LENGTH];
	strcpy(buffer,(LPCTSTR)strItem);
	buffer[strItem.GetLength()]='\0';
	//每48个字符为一行 分别显示http内容
	for (int i=0;i<strItem.GetLength()/48;i++)
	{
		m_tree.InsertItem(CString(buffer + i*48).Left(48), 10,10,httpRoot,TVI_LAST);
	}
	//最后不满48个字符 单独一行
	if (strItem.GetLength()%48)
	{
		m_tree.InsertItem(CString(buffer + i*48), 10,10,httpRoot,TVI_LAST);
	}
	UpdateData(FALSE);
	*pResult = 0;
}
//UDP
void CProtocolAnalysisDlg::OnClickListUdp(NMHDR* pNMHDR, LRESULT* pResult) 
{
	// TODO: Add your control notification handler code here
	int nItem = m_list_udp.GetNextItem( -1, LVNI_ALL | LVNI_SELECTED);
	if (nItem == -1)
		return ;
	MessageBeep(65);
	RAW_PACKET* pRawPacket = (RAW_PACKET*)(m_list_udp.GetItemData(nItem));
	ShowPacketInfo(pRawPacket);
	ShowIpInfo(pRawPacket->ip_seq);//根据其ip层的序号求其ip信息
	ShowUdpInfo(pRawPacket->tcpOrUdp_seq);//根据其传输层序号显示其 udp信息
	UpdateData(FALSE);	
	*pResult = 0;
}
//DNS
void CProtocolAnalysisDlg::OnClickListDns(NMHDR* pNMHDR, LRESULT* pResult) 
{
	// TODO: Add your control notification handler code here
	int nItem = m_list_Dns.GetNextItem( -1, LVNI_ALL | LVNI_SELECTED);
	if (nItem == -1)
		return ;
	MessageBeep(65);
	RAW_PACKET* pRawPacket = (RAW_PACKET*)(m_list_Dns.GetItemData(nItem));
	ShowPacketInfo(pRawPacket);
	ShowIpInfo(pRawPacket->ip_seq);//根据其ip层的序号求其ip信息
	ShowUdpInfo(pRawPacket->tcpOrUdp_seq);//根据其传输层序号显示其 udp信息
	//一下为详细显示下DNS 的信息
	CString strItem;
	HTREEITEM DnsHdrRoot=m_tree.InsertItem(_T("DNS"), 1,1,m_TreeRoot,TVI_LAST);
	strItem.Format("标识: %s",m_list_Dns.GetItemText(nItem,1));//
	m_tree.InsertItem(strItem, 3,3,DnsHdrRoot,TVI_LAST);
	strItem.Format("QR(标志): %s",m_list_Dns.GetItemText(nItem,2));//
	m_tree.InsertItem(strItem, 9,9,DnsHdrRoot,TVI_LAST);
	strItem.Format("opcode(标志): %s",m_list_Dns.GetItemText(nItem,3));//
	m_tree.InsertItem(strItem, 9,9,DnsHdrRoot,TVI_LAST);
		strItem.Format("AA(标志): %s",m_list_Dns.GetItemText(nItem,4));//
	m_tree.InsertItem(strItem, 9,9,DnsHdrRoot,TVI_LAST);
		strItem.Format("TC(标志): %s",m_list_Dns.GetItemText(nItem,5));//
	m_tree.InsertItem(strItem, 9,9,DnsHdrRoot,TVI_LAST);
		strItem.Format("RD(标志): %s",m_list_Dns.GetItemText(nItem,6));//
	m_tree.InsertItem(strItem, 9,9,DnsHdrRoot,TVI_LAST);
		strItem.Format("RA(标志): %s",m_list_Dns.GetItemText(nItem,7));//
	m_tree.InsertItem(strItem, 9,9,DnsHdrRoot,TVI_LAST);
	strItem.Format("zero(标志): %s",m_list_Dns.GetItemText(nItem,8));//
	m_tree.InsertItem(strItem, 9,9,DnsHdrRoot,TVI_LAST);
		strItem.Format("rcode(标志): %s",m_list_Dns.GetItemText(nItem,9));//
	m_tree.InsertItem(strItem, 9,9,DnsHdrRoot,TVI_LAST);
		strItem.Format("问题数: %s",m_list_Dns.GetItemText(nItem,10));//
	m_tree.InsertItem(strItem, 2,2,DnsHdrRoot,TVI_LAST);
		strItem.Format("资源记录数: %s",m_list_Dns.GetItemText(nItem,11));//
	m_tree.InsertItem(strItem, 2,2,DnsHdrRoot,TVI_LAST);
		strItem.Format("授权资源记录数: %s",m_list_Dns.GetItemText(nItem,12));//
	m_tree.InsertItem(strItem, 2,2,DnsHdrRoot,TVI_LAST);
		strItem.Format("额外资源记录数: %s",m_list_Dns.GetItemText(nItem,13));//
	m_tree.InsertItem(strItem, 2,2,DnsHdrRoot,TVI_LAST);
	UpdateData(FALSE);	
	*pResult = 0;
}

void CProtocolAnalysisDlg::ReleaseAll()
{
	for(int i=0;i<m_list_common.GetItemCount();i++)
	{
		if (m_list_common.GetItemData(i))
		{
			RAW_PACKET *p =(RAW_PACKET*)(m_list_common.GetItemData(i));
			delete [](p->pPktData);//释放申请的内存
			delete p;
			p=NULL;
		}
		m_list_common.SetItemData(i,0);
	}
}

void CProtocolAnalysisDlg::OnBtclear() 
{
	// TODO: Add your control notification handler code here
	ReleaseAll();
	m_list_common.DeleteAllItems();
	m_list_arp.DeleteAllItems();
	m_list_ethernet.DeleteAllItems();
	m_list_ip.DeleteAllItems();
	m_list_tcp.DeleteAllItems();
	m_list_udp.DeleteAllItems();
	m_list_icmp.DeleteAllItems();
	m_list_http.DeleteAllItems();
	m_list_Dns.DeleteAllItems();
	m_tree.DeleteAllItems();
	m_EditCtrl.SetWindowText(_T(""));
	m_nPacket=m_nArp=m_nIp=m_nHttp=0;
	m_Ethernet=m_nTcp=m_nUdp=m_nIcmp=0;
	CStatic *p=(CStatic *)GetDlgItem(IDC_STATIC_PACKET_COUNT);
	p->SetWindowText (_T("数据包个数: 0"));
	UpdateWindow();
}

void CProtocolAnalysisDlg::OnRestart() 
{
	// TODO: Add your command handler code here
	OnBtclear();
	OnStart();
}
//cListCtrl的一些使用方法
//http://wenku.baidu.com/view/3bf601ddd15abe23482f4d79.html 
void CProtocolAnalysisDlg::OnmenuFirst() 
{
	// TODO: Add your command handler code here
	m_pCurrentList->SetFocus();
	m_pCurrentList->EnsureVisible(0,FALSE);//显示首条

}

void CProtocolAnalysisDlg::OnmenuLast() 
{
	// TODO: Add your command handler code here
	m_pCurrentList->SetFocus();
	m_pCurrentList->EnsureVisible(m_pCurrentList->GetItemCount()-1,FALSE);
}

void CProtocolAnalysisDlg::OnmenuCenter() 
{
	// TODO: Add your command handler code here
	m_pCurrentList->SetFocus();
	m_pCurrentList->EnsureVisible(m_pCurrentList->GetItemCount()/2,FALSE);
}

bool CProtocolAnalysisDlg::TrayMyIcon(bool bAdd)
{
	BOOL bRet = false;
	m_Ntnd.cbSize = sizeof(NOTIFYICONDATA); //设置任务托盘有关结构大小
	m_Ntnd.hWnd = GetSafeHwnd(); // 如果对托盘中的图标进行操作，相应的消息就传给这个句柄所代表的窗口
	m_Ntnd.uID = IDR_MAINFRAME; // 设置托盘图标ID
	if ( bAdd == TRUE )
	{
		// 这个成员标志着其他哪些成员的数据是有效的，分别为
		// NIF_ICON, NIF_MESSAGE, NIF_TIP，分别代表着数据有效的成员是hIcon, uCallbackMessage, szTip
		m_Ntnd.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
		// 这是个消息标志，当用鼠标对托盘区相应图标进行操作的时候，就会传递消息给Hwnd所代表的窗口
		m_Ntnd.uCallbackMessage = WM_TRAYICON_MSG; ;// 自定义的消息名称
		// 要增加，删除或修改的图标句柄
		m_Ntnd.hIcon = LoadIcon(AfxGetInstanceHandle(), MAKEINTRESOURCE(IDR_MAINFRAME));
		// 鼠标移动到托盘图标上时的提示文字
		strncpy(m_Ntnd.szTip, _T("网络包截获分析系统"), sizeof(m_Ntnd.szTip));
		ShowWindow(SW_MINIMIZE);// 最小化
		ShowWindow(SW_HIDE);// 隐藏主窗口
		bRet = Shell_NotifyIcon(NIM_ADD, &m_Ntnd);// 向系统传递消息，以添加托盘区的图标
	}
	else
	{
		ShowWindow(SW_SHOWNA); // 显示窗口
		SetForegroundWindow(); // 把窗口设置在前
		bRet = Shell_NotifyIcon(NIM_DELETE, &m_Ntnd);// 向系统传递消息 删除托盘区的图标
	}
	return bRet;
}
// 当用户用鼠标点击托盘区的图标的时候(无论是左键还是右键),会向hWnd所代表的窗口传送消息
LRESULT CProtocolAnalysisDlg::OnTrayCallBackMsg(WPARAM wparam, LPARAM lparam)
{
	//wParam接收的是图标的ID，而lParam接收的是鼠标的行为
	if(wparam!=IDR_MAINFRAME)
		return 0;
	switch(lparam)
	{
	case WM_RBUTTONUP:
		{
			CMenu mMenu, *pMenu = NULL;
			CPoint pt;
			mMenu.LoadMenu(IDR_MENU2);
			pMenu = mMenu.GetSubMenu(0);
			GetCursorPos(&pt);//得到鼠标位置
			SetForegroundWindow();
			//确定弹出式菜单的位置
			pMenu->TrackPopupMenu(TPM_LEFTALIGN | TPM_RIGHTBUTTON, pt.x, pt.y, this);
			//资源回收
			HMENU hmenu=mMenu.Detach();
			mMenu.DestroyMenu();
			break;
		}
	case WM_LBUTTONDBLCLK: // 单击任务托盘图标
		ShowWindow(SW_RESTORE);// 激活窗口
		SetForegroundWindow(); // 显示最前
		TrayMyIcon(false);  // 取消托盘
		break;
	default:
		break;
	}
	return 1;
}
//显示主程序界面
void CProtocolAnalysisDlg::OnMenuShow() 
{
	// TODO: Add your command handler code here
	ShowWindow(SW_RESTORE); // 显示窗口
	TrayMyIcon(FALSE);// 取消托盘
}
//退出程序
void CProtocolAnalysisDlg::OnMenuQuit() 
{
	// TODO: Add your command handler code here
	PostMessage(WM_CLOSE,0,0);
}

void CProtocolAnalysisDlg::OnIfSave() 
{
	// TODO: Add your command handler code here
	// 根据上次选择设置 Check  状态
	UINT state = m_Psubmenu->GetMenuState(MENU_IF_SAVE, MF_BYCOMMAND);
	ASSERT(state != 0xFFFFFFFF);
	if (state & MF_CHECKED)
	{
		m_Psubmenu->CheckMenuItem(MENU_IF_SAVE, MF_UNCHECKED | MF_BYCOMMAND);
		m_SaveDumpFile=false;
	}
	else
	{
		m_Psubmenu->CheckMenuItem(MENU_IF_SAVE, MF_CHECKED | MF_BYCOMMAND);
		m_SaveDumpFile=true;
	}
}
//处理列表框鼠标右击消息
void CProtocolAnalysisDlg::ProcessRClickList()//iSubItem从0开始
{
	  int nCount= 0;
	  /*获取列表视图控件的标题控件*/
	  CHeaderCtrl *pHeaderCtrl =m_pCurrentList->GetHeaderCtrl(); 
	  /*"标头控件"是一个窗口,通常在文本或数据顶部,它包含列名字,可
	  以被拆分,用户可以拖动分隔线来分开各个部分,以设置各列的宽度*/
	  if(pHeaderCtrl!= NULL)
		  nCount = pHeaderCtrl->GetItemCount();//获得一行有多少列
	  if (m_iSubItem<nCount)//浮动菜单只显示列框仅有的列上
	  {
		  DWORD dwPos = GetMessagePos();
		  CPoint point( LOWORD(dwPos), HIWORD(dwPos) );
		  CMenu menu;
		  VERIFY( menu.LoadMenu(IDR_MENU3));
		  CMenu* popup = menu.GetSubMenu(0);
		  ASSERT( popup != NULL );
		  /*弹出浮动菜单*/
		  popup->TrackPopupMenu(TPM_LEFTALIGN | TPM_RIGHTBUTTON, point.x, point.y,this);
	  }
}
//处理复制菜单消息
void CProtocolAnalysisDlg::OnCopy() 
{
	// TODO: Add your command handler code here
	if(OpenClipboard())//打开剪贴板
	{
		CString str;
		HANDLE hClip;
		char *pBuf;
		EmptyClipboard();//清空剪贴板
		str=m_pCurrentList->GetItemText(m_nItem,m_iSubItem);//获得文本
		hClip=::GlobalAlloc(GMEM_MOVEABLE,str.GetLength()+1);//从堆中分配内存
		pBuf=(char*)GlobalLock(hClip);//对内存加锁
		strcpy(pBuf,str);//拷贝到分配的内存中
		GlobalUnlock(hClip);//解锁
		SetClipboardData(CF_TEXT,hClip);
		CloseClipboard();//关闭剪贴板
	}
}
void CProtocolAnalysisDlg::OnRclickListCom(NMHDR* pNMHDR, LRESULT* pResult) 
{
	// TODO: Add your control notification handler code here
	NM_LISTVIEW* pNMListView = (NM_LISTVIEW*)pNMHDR;
    m_nItem = pNMListView->iItem;
	m_iSubItem =pNMListView->iSubItem;
	if (m_nItem != -1)
	{
		ProcessRClickList();
	}
	*pResult = 0;
}

void CProtocolAnalysisDlg::OnRclickListPppoe(NMHDR* pNMHDR, LRESULT* pResult) 
{
	// TODO: Add your control notification handler code here
	NM_LISTVIEW* pNMListView = (NM_LISTVIEW*)pNMHDR;
    m_nItem = pNMListView->iItem;
	m_iSubItem =pNMListView->iSubItem;
	if (m_nItem != -1)
	{
		ProcessRClickList();
	}
	*pResult = 0;
}

void CProtocolAnalysisDlg::OnRclickListIp(NMHDR* pNMHDR, LRESULT* pResult) 
{
	// TODO: Add your control notification handler code here
	NM_LISTVIEW* pNMListView = (NM_LISTVIEW*)pNMHDR;
    m_nItem = pNMListView->iItem;
	m_iSubItem =pNMListView->iSubItem;
	if (m_nItem != -1)
	{
		ProcessRClickList();
	}
	*pResult = 0;
}

void CProtocolAnalysisDlg::OnRclickListArp(NMHDR* pNMHDR, LRESULT* pResult) 
{
	// TODO: Add your control notification handler code here
	NM_LISTVIEW* pNMListView = (NM_LISTVIEW*)pNMHDR;
    m_nItem = pNMListView->iItem;
	m_iSubItem =pNMListView->iSubItem;
	if (m_nItem != -1)
	{
		ProcessRClickList();
	}
	*pResult = 0;
}

void CProtocolAnalysisDlg::OnRclickListIcmp(NMHDR* pNMHDR, LRESULT* pResult) 
{
	// TODO: Add your control notification handler code here
	NM_LISTVIEW* pNMListView = (NM_LISTVIEW*)pNMHDR;
    m_nItem = pNMListView->iItem;
	m_iSubItem =pNMListView->iSubItem;
	if (m_nItem != -1)
	{
		ProcessRClickList();
	}
	*pResult = 0;
}

void CProtocolAnalysisDlg::OnRclickListTcp(NMHDR* pNMHDR, LRESULT* pResult) 
{
	// TODO: Add your control notification handler code here
	NM_LISTVIEW* pNMListView = (NM_LISTVIEW*)pNMHDR;
    m_nItem = pNMListView->iItem;
	m_iSubItem =pNMListView->iSubItem;
	if (m_nItem != -1)
	{
		ProcessRClickList();
	}
	*pResult = 0;
}

void CProtocolAnalysisDlg::OnRclickListUdp(NMHDR* pNMHDR, LRESULT* pResult) 
{
	// TODO: Add your control notification handler code here
	NM_LISTVIEW* pNMListView = (NM_LISTVIEW*)pNMHDR;
    m_nItem = pNMListView->iItem;
	m_iSubItem =pNMListView->iSubItem;
	if (m_nItem != -1)
	{
		ProcessRClickList();
	}
	*pResult = 0;
}

void CProtocolAnalysisDlg::OnRclickListHttp(NMHDR* pNMHDR, LRESULT* pResult) 
{
	// TODO: Add your control notification handler code here
	NM_LISTVIEW* pNMListView = (NM_LISTVIEW*)pNMHDR;
    m_nItem = pNMListView->iItem;
	m_iSubItem =pNMListView->iSubItem;
	if (m_nItem != -1)
	{
		ProcessRClickList();
	}
	*pResult = 0;
}
void CProtocolAnalysisDlg::OnRclickListDns(NMHDR* pNMHDR, LRESULT* pResult) 
{
	// TODO: Add your control notification handler code here
	NM_LISTVIEW* pNMListView = (NM_LISTVIEW*)pNMHDR;
    m_nItem = pNMListView->iItem;
	m_iSubItem =pNMListView->iSubItem;
	if (m_nItem != -1)
	{
		ProcessRClickList();
	}
	*pResult = 0;
}

void CProtocolAnalysisDlg::OnSkin() 
{
	// TODO: Add your control notification handler code here
	DWORD dwPos = GetMessagePos();
	CPoint point( LOWORD(dwPos), HIWORD(dwPos));
	CMenu menu;
	VERIFY( menu.LoadMenu(IDR_MENU4));
	CMenu* popup = menu.GetSubMenu(0);
	ASSERT( popup != NULL );
	/*弹出浮动菜单*/
	popup->TrackPopupMenu(TPM_LEFTALIGN | TPM_RIGHTBUTTON, point.x, point.y,this);
}

void CProtocolAnalysisDlg::OnSkin1() 
{
	// TODO: Add your command handler code here
	pSkinFun(_T("skin\\royale.she"), NULL);

}

void CProtocolAnalysisDlg::OnSkin2() 
{
	// TODO: Add your command handler code here
	pSkinFun(_T("skin\\homestead.she"), NULL);
}

void CProtocolAnalysisDlg::OnSkin3() 
{
	// TODO: Add your command handler code here
	pSkinFun(_T("skin\\skinh.she"), NULL);
}

void CProtocolAnalysisDlg::OnSkin4() 
{
	// TODO: Add your command handler code here
	pSkinFun(_T("skin\\china.she"), NULL);
}

void CProtocolAnalysisDlg::OnSkinRe() 
{
	// TODO: Add your command handler code here
	pSkinFun(_T("skin\\pixos.she"), NULL);
}
/*处理双击树节点,此时在原始数据中选中所选的报文*/
void CProtocolAnalysisDlg::OnDblclkTree(NMHDR* pNMHDR, LRESULT* pResult) 
{
	// TODO: Add your control notification handler code here
	HTREEITEM hTreeItem = m_tree.GetSelectedItem();
	CString str=m_tree.GetItemText(hTreeItem);//获得选中的节点文本
	int start=0,end=0;
	/*根据节点的文本值判断为什么协议报文*/
	if (str.Find("MAC header",0)!=-1)
	{
		start=5;
		end=46;
	}
	else if(str.Find("ARP",0)!=-1 || str.Find("RARP",0)!=-1)
	{
		start=47;
		end=176;
	}
	else if(str.Find("IPV4",0)!=-1)
	{
		start=47;
		end=152;
	}
	else if(str.Find("ICMP",0)!=-1)
	{
		start=153;
		end=165;
	}
	else if(str.Find("UDP",0)!=-1)
	{
		start=153;
		end=176;
	}
	else if(str.Find("TCP",0)!=-1)
	{
		start=153;
		end=235;
	}
	else if(str.Find("HTTP",0)!=-1)
	{
		start=236;
		end=-1;
	}
	else if(str.Find("DNS",0)!=-1)
	{
		start=177;
		end=-1;
	}
	m_EditCtrl.HideSelection(FALSE, FALSE);
	m_EditCtrl.SetSel(start, end); //设置处理区域
	*pResult = 0;
}

