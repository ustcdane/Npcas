// OpenScreenWnd.cpp : implementation file
//

#include "stdafx.h"
#include "ProtocolAnalysis.h"
#include "OpenScreenWnd.h"
#include <ctime>
#include <cstdlib>
#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// COpenScreenWnd

COpenScreenWnd::COpenScreenWnd()
{
	m_bitmap.LoadBitmap(IDB_BITMAP1);// 拷贝资源位图
    m_bitmap.GetBitmap(&m_bm);// 得到位图结构中的大小信息
}

COpenScreenWnd::~COpenScreenWnd()
{
}
BEGIN_MESSAGE_MAP(COpenScreenWnd, CWnd)
	//{{AFX_MSG_MAP(COpenScreenWnd)
	ON_WM_PAINT()
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()


/////////////////////////////////////////////////////////////////////////////
// COpenScreenWnd message handlers
void COpenScreenWnd::CreatScreenWnd()
{
	//建立大小与位图大小相同的窗口
	CreateEx(0,AfxRegisterWndClass(0,AfxGetApp()->LoadStandardCursor(IDC_ARROW)),
		"ImageScreen",
		WS_POPUP,
		0,
		0,
		m_bm.bmWidth,
		m_bm.bmHeight,
		NULL,
		NULL,
		NULL );
}

void COpenScreenWnd::OnPaint() 
{
	CPaintDC dc(this); // device context for painting
	
	// TODO: Add your message handler code here
	m_MemDC.CreateCompatibleDC(NULL);// 建立一个和dc兼容的内存DC放置位图
	old_bitmap=m_MemDC.SelectObject(&m_bitmap);// 将创建的位图选入内存DC
	
	int stepx,stepy,dispnum,x,y; 
	int bit_Arry[20][20];      // 数组记录已显示过的数据组 
	memset(bit_Arry,0,sizeof(bit_Arry)); 
	stepx=m_bm.bmWidth/20; 
	stepy=m_bm.bmHeight/20; 
	srand( (unsigned)time( NULL ) ); 
	dispnum=0; 
	//记录已显示过的数据组的个数 
	while(true) 
		
	{
		x=rand()%20; 
		
		y=rand()%20; 
		
		if ( bit_Arry[x][y] ) //如果为1，则已经显示了，跳出循环。
			continue; 
		bit_Arry[x][y]=1; //显示，设置为1
		dc.StretchBlt( x*stepx, y*stepy, //目标设备逻辑横、纵坐标 
			stepx,stepy, //显示位图的像素宽、高度 
			&m_MemDC, // 位图内存设备对象 
			x*stepx, y*stepy, // 位图的起始横、纵坐标 
			stepx,stepy, // 位图的像素宽、高度 
			SRCCOPY); // 将源矩形区域直接拷贝到目标矩形区域
		dispnum++; 
		if ( dispnum >=400 ) // 判断显示完背景图吗
			break; // 跳出循环
		Sleep(2); 
	}// while
	Sleep(160);// 暂停 160毫秒
	m_MemDC.SelectObject(old_bitmap); // 还原DC
	// Do not call CWnd::OnPaint() for painting messages
}
