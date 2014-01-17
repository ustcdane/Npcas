// helpdialog.cpp : implementation file
//

#include "stdafx.h"
#include "Protocolanalysis.h"
#include "helpdialog.h"


#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// Chelpdialog dialog

Chelpdialog::Chelpdialog(CWnd* pParent /*=NULL*/) : CDialog(Chelpdialog::IDD, pParent)
{
	//{{AFX_DATA_INIT(Chelpdialog)
	//}}AFX_DATA_INIT
	
}

void Chelpdialog::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(Chelpdialog)
	//}}AFX_DATA_MAP
	
}


BEGIN_MESSAGE_MAP(Chelpdialog, CDialog)
//{{AFX_MSG_MAP(Chelpdialog)
ON_WM_PAINT()
	ON_WM_LBUTTONDOWN()
	ON_WM_MOUSEMOVE()
	ON_WM_CANCELMODE()
	ON_WM_CTLCOLOR()
	ON_WM_CAPTURECHANGED()
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// Chelpdialog message handlers

void Chelpdialog::OnOK()
{
	CDialog::OnOK();
}

BOOL Chelpdialog::OnInitDialog()
{
	CDialog::OnInitDialog();
	HICON m_hIcon;	
	m_hIcon = AfxGetApp()->LoadIcon(IDI_ICON1);
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon
	CenterWindow();
	//����̬�ı�����Ļ��������m_pRectLink��    
     GetDlgItem(IDC_ABOUT_MY) -> GetWindowRect(&m_pRectLink);    
    //����Ļ����ת��Ϊ�ͻ�����    
     ScreenToClient(&m_pRectLink); 
	return TRUE;
}

void Chelpdialog::OnPaint()
{
	CPaintDC dc(this);
}

void Chelpdialog::OnLButtonDown(UINT nFlags, CPoint point) 
{
	// TODO: Add your message handler code here and/or call default
	//�˴�����ж������㷨    
    if (point.x > m_pRectLink.left && point.x < m_pRectLink.right && point.y > m_pRectLink.top && point.y < m_pRectLink.bottom)    
	{    
        //����������    
        if (nFlags == MK_LBUTTON)       
		{    
            //Ϊ�������Ч�����˴��������ϱ任�����״�Ĵ���    
			ShellExecute(0, NULL, _T("http://blog.csdn.net/gfsfg8545/article/details/7522731"),
				NULL,NULL, SW_NORMAL);        
		}    
	}    
	CDialog::OnLButtonDown(nFlags, point);
}

void Chelpdialog::OnMouseMove(UINT nFlags, CPoint point) 
{
	// TODO: Add your message handler code here and/or call default
		   //������������ھ�̬�ı���ʱ����������С��״    
    if (point.x > m_pRectLink.left && point.x < m_pRectLink.right && point.y > m_pRectLink.top && point.y < m_pRectLink.bottom )    
    //�˴�����ж������㷨    
     {    
        HCURSOR hCursor;    
         hCursor = AfxGetApp()->LoadStandardCursor(IDC_HAND);    
        //�������ΪС��״    
         SetCursor(hCursor);    
     }    
 
	CDialog::OnMouseMove(nFlags, point);
}

void Chelpdialog::OnCancelMode() 
{
	CDialog::OnCancelMode();
	
	// TODO: Add your message handler code here
	
}

HBRUSH Chelpdialog::OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor) 
{
	HBRUSH hbr = CDialog::OnCtlColor(pDC, pWnd, nCtlColor);
	// TODO: Change any attributes of the DC here
	if (pWnd->GetDlgCtrlID()==IDC_ABOUT_MY)
	{
		pDC-> SetBkMode(TRANSPARENT); 
		pDC-> SetBkColor (RGB(189,213,247));      //���ñ��� 
		pDC-> SetTextColor(RGB(150,0,0));          //�������� 
		HBRUSH temp = CreateSolidBrush(RGB(189,213,247)); 
		return temp; 
	}
	// TODO: Return a different brush if the default is not desired
	return hbr;
}

void Chelpdialog::OnCaptureChanged(CWnd *pWnd) 
{
	// TODO: Add your message handler code here
	
	CDialog::OnCaptureChanged(pWnd);
}
