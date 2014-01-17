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
	m_bitmap.LoadBitmap(IDB_BITMAP1);// ������Դλͼ
    m_bitmap.GetBitmap(&m_bm);// �õ�λͼ�ṹ�еĴ�С��Ϣ
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
	//������С��λͼ��С��ͬ�Ĵ���
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
	m_MemDC.CreateCompatibleDC(NULL);// ����һ����dc���ݵ��ڴ�DC����λͼ
	old_bitmap=m_MemDC.SelectObject(&m_bitmap);// ��������λͼѡ���ڴ�DC
	
	int stepx,stepy,dispnum,x,y; 
	int bit_Arry[20][20];      // �����¼����ʾ���������� 
	memset(bit_Arry,0,sizeof(bit_Arry)); 
	stepx=m_bm.bmWidth/20; 
	stepy=m_bm.bmHeight/20; 
	srand( (unsigned)time( NULL ) ); 
	dispnum=0; 
	//��¼����ʾ����������ĸ��� 
	while(true) 
		
	{
		x=rand()%20; 
		
		y=rand()%20; 
		
		if ( bit_Arry[x][y] ) //���Ϊ1�����Ѿ���ʾ�ˣ�����ѭ����
			continue; 
		bit_Arry[x][y]=1; //��ʾ������Ϊ1
		dc.StretchBlt( x*stepx, y*stepy, //Ŀ���豸�߼��ᡢ������ 
			stepx,stepy, //��ʾλͼ�����ؿ��߶� 
			&m_MemDC, // λͼ�ڴ��豸���� 
			x*stepx, y*stepy, // λͼ����ʼ�ᡢ������ 
			stepx,stepy, // λͼ�����ؿ��߶� 
			SRCCOPY); // ��Դ��������ֱ�ӿ�����Ŀ���������
		dispnum++; 
		if ( dispnum >=400 ) // �ж���ʾ�걳��ͼ��
			break; // ����ѭ��
		Sleep(2); 
	}// while
	Sleep(160);// ��ͣ 160����
	m_MemDC.SelectObject(old_bitmap); // ��ԭDC
	// Do not call CWnd::OnPaint() for painting messages
}
