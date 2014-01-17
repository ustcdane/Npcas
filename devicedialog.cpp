// DeviceDialog.cpp : implementation file
//

#include "stdafx.h"
#include "protocolanalysis.h"
#include "Protocolanalysisdlg.h"
#include "DeviceDialog.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif
extern HWND g_hWnd;
extern int g_network_device;
extern char  g_network_device_name[1024][1024];
extern int g_network_device_number;
/////////////////////////////////////////////////////////////////////////////
// CDeviceDialog dialog


CDeviceDialog::CDeviceDialog(CWnd* pParent /*=NULL*/)
	: CDialog(CDeviceDialog::IDD, pParent)
{
	//{{AFX_DATA_INIT(CDeviceDialog)
		// NOTE: the ClassWizard will add member initialization here
	//}}AFX_DATA_INIT
}


void CDeviceDialog::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CDeviceDialog)
	DDX_Control(pDX, IDC_LIST_DEVICE, m_list_device);
	//}}AFX_DATA_MAP
}


BEGIN_MESSAGE_MAP(CDeviceDialog, CDialog)
	//{{AFX_MSG_MAP(CDeviceDialog)
	ON_WM_CTLCOLOR()
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CDeviceDialog message handlers

BOOL CDeviceDialog::OnInitDialog() 
{
	CDialog::OnInitDialog();
	
	// TODO: Add extra initialization here
	for(int i=0;i<g_network_device_number;i++)
	{
		m_list_device.InsertString (0,g_network_device_name[i]);
	}
	return TRUE;  // return TRUE unless you set the focus to a control
	              // EXCEPTION: OCX Property Pages should return FALSE
}

void CDeviceDialog::OnOK() 
{
	UpdateData(TRUE);
	// TODO: Add extra validation here
	g_network_device=m_list_device.GetCurSel();
	if(g_network_device==-1)
	{
		MessageBox("请选择网络接口","网络协议分析系统");
		return ;
	}
	g_network_device++;
	CProtocolAnalysisDlg *p1=(CProtocolAnalysisDlg *)GetParent();
	CButton *p=(CButton*)p1->GetDlgItem (IDC_BUTTON_START);
	p->EnableWindow (FALSE);
	CMenu *pp=(CMenu *)p1->GetMenu();
	pp->EnableMenuItem (MENU_START,TRUE);
	CButton *p2=(CButton*)p1->GetDlgItem (IDC_BUTTON_END);
	p2->EnableWindow (TRUE);
	CMenu *pp2=(CMenu *)p1->GetMenu();
	pp2->EnableMenuItem (MENU_STOP,FALSE);
	CDialog::OnOK();
}


HBRUSH CDeviceDialog::OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor) 
{
	HBRUSH hbr = CDialog::OnCtlColor(pDC, pWnd, nCtlColor);
	
	// TODO: Change any attributes of the DC here 
	if(nCtlColor==CTLCOLOR_LISTBOX) //判断是否为 listbox
	{ 
		pDC-> SetBkMode(TRANSPARENT); 
		pDC-> SetBkColor (RGB(189,213,247));      //设置背景 
		pDC-> SetTextColor(RGB(150,0,0));          //设置字体 
		HBRUSH temp = CreateSolidBrush(RGB(189,213,247)); 
		return temp; 
	} 
	// TODO: Return a different brush if the default is not desired
	return hbr;
}
