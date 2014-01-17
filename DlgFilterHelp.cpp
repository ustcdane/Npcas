// DlgFilterHelp.cpp : implementation file
//

#include "stdafx.h"
#include "protocolanalysis.h"
#include "DlgFilterHelp.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// CDlgFilterHelp dialog
CDlgFilterHelp::CDlgFilterHelp(CWnd* pParent /*=NULL*/)
	: CDialog(CDlgFilterHelp::IDD, pParent)
{
	//{{AFX_DATA_INIT(CDlgFilterHelp)
		// NOTE: the ClassWizard will add member initialization here
	//}}AFX_DATA_INIT
}
void CDlgFilterHelp::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CDlgFilterHelp)
	DDX_Control(pDX, IDC_RICHEDIT_HELP, m_EditHelp);
	//}}AFX_DATA_MAP
}


BEGIN_MESSAGE_MAP(CDlgFilterHelp, CDialog)
	//{{AFX_MSG_MAP(CDlgFilterHelp)
	ON_WM_MOUSEMOVE()
	ON_WM_LBUTTONDOWN()
	ON_WM_CTLCOLOR()
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CDlgFilterHelp message handlers

BOOL CDlgFilterHelp::OnInitDialog() 
{
	CDialog::OnInitDialog();
	
	// TODO: Add extra initialization here
	CHARFORMAT cf;
	//编辑控件
		//初始化字体及颜色
	ZeroMemory(&cf, sizeof(CHARFORMAT));
	cf.cbSize = sizeof(CHARFORMAT);
	cf.dwMask = CFM_BOLD | CFM_COLOR | CFM_FACE |
		CFM_ITALIC | CFM_SIZE | CFM_UNDERLINE;
	cf.dwEffects = 0;
	cf.yHeight = 16*15;//文字高度
	cf.crTextColor = RGB(20, 30, 120); //文字颜色
	strcpy(cf.szFaceName ,_T("隶书"));//设置字体
	m_EditHelp.SetDefaultCharFormat(cf);
	CString str;
	str  = _T("1,你可以在常用过滤规则中选择过滤规则名,下方的编辑框将显示\r\n");
	str += _T("过滤语句,你可以修改此过滤语句并进行相应规则的包捕获。\r\n");
	str += _T("2,你可以在下方的编辑框(过滤规则名,过滤语句)输入自己的常用\r\n");
	str += _T("的过滤规则,并单击左方的编辑框中的添加按钮,添加自己的规则。\r\n");
	str += _T("当下方的编辑框为空时,点击添加时new,new为你添加的内容。\r\n");
	str += _T("3,当选中一项常用规则并且你以后不常用时,你可以单击左上方的\r\n");
	str += _T("删除按钮删除此项。\r\n\r\n");
	str += _T("---------------------------------------------------------\r\n");
	str += _T("4,过滤表达式的基本组成元素为关键词,个表达式由一个或多个关\r\n");
	str += _T("键词组成,键词之间通过and、or和not连接。关键词主要有两类：\r\n");
	str += _T("第一类 声明数据包源或目的地的关键词.关键词host,net和port分\r\n");
	str += _T("别指明依据收、发方IP地址（或主机名）,网络地址和端口号进行\r\n");
	str += _T("判断,若未指定,则默认为host;关键词前加上修饰词dst,src和dst\r\n");
	str += _T("or src指明捕获特定方向的数据,若未指定,则默认为dst or src。\r\n");
    str += _T("如\"dst host 210.31.234.254\",\"port 80\",\"src 210.31.234.13\"。\r\n"); 
	str += _T("第二类 声明数据包协议类型的关键词.关键词ether、fddi、tr、ip\r\n");
	str += _T("、ip6、arp、rarp、tcp和udp分别指明数据链路层,网络层和传输\r\n");
	str += _T("层所用协议类型.IP分组类型的ip proto等.如“ether proto \\a\r\nrp”、");
	str += _T("”,“ip proto \\tcp”。\r\n");
	m_EditHelp.SetWindowText(str);
	//将静态文本的屏幕坐标存放在m_pRectLink中    
     GetDlgItem(IDC_LINK) -> GetWindowRect(&m_pRectLink);    
    //将屏幕坐标转换为客户坐标    
     ScreenToClient(&m_pRectLink); 
	 m_font.CreatePointFont(120,"华文行楷");
	return TRUE;  // return TRUE unless you set the focus to a control
	              // EXCEPTION: OCX Property Pages should return FALSE
}

void CDlgFilterHelp::OnMouseMove(UINT nFlags, CPoint point) 
{
	// TODO: Add your message handler code here and/or call default
	   //下面设置鼠标在静态文本区时，将光标设成小手状    
    if (point.x > m_pRectLink.left && point.x < m_pRectLink.right && point.y > m_pRectLink.top && point.y < m_pRectLink.bottom )    
    //此处添加判断坐标算法    
     {    
        HCURSOR hCursor;    
         hCursor = AfxGetApp()->LoadStandardCursor(IDC_HAND);    
        //将鼠标设为小手状    
         SetCursor(hCursor);    
     }    
 
	CDialog::OnMouseMove(nFlags, point);
}

void CDlgFilterHelp::OnLButtonDown(UINT nFlags, CPoint point) 
{
	// TODO: Add your message handler code here and/or call default
	//此处添加判断坐标算法    
    if (point.x > m_pRectLink.left && point.x < m_pRectLink.right && point.y > m_pRectLink.top && point.y < m_pRectLink.bottom)    
	{    
        //鼠标左键按下    
        if (nFlags == MK_LBUTTON)       
		{    
            //为改善鼠标效果，此处加入以上变换鼠标形状的代码    
			ShellExecute(0, NULL, _T("http://blog.csdn.net/gfsfg8545/article/details/7490944"),
				NULL,NULL, SW_NORMAL);        
		}    
	}    
	CDialog::OnLButtonDown(nFlags, point);
}

HBRUSH CDlgFilterHelp::OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor) 
{
	HBRUSH hbr = CDialog::OnCtlColor(pDC, pWnd, nCtlColor);
	
	// TODO: Change any attributes of the DC here
	if (pWnd->GetDlgCtrlID()==IDC_LINK)
	{
		pDC->SetBkMode(TRANSPARENT);
		pDC->SetTextColor(RGB(0,255,0));  //设置字体颜色
		pDC->SelectObject(&m_font);
		HBRUSH   temp=CreateSolidBrush(RGB(255,255,255));
		// TODO: Return a different brush if the default is not desired
		return temp;  
	}
	// TODO: Return a different brush if the default is not desired
	return hbr;
}
