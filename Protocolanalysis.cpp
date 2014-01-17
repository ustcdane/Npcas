// ProtocolAnalysis.cpp : Defines the class behaviors for the application.
//

#include "stdafx.h"
#include "Protocolanalysis.h"
#include "OpenScreenWnd.h"
#include "ProtocolanalysisDlg.h"


#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
char lwtGlobal_FilePath[_MAX_PATH];
char Global_FileDirectory[MAX_PATH];


BEGIN_MESSAGE_MAP(CProtocolAnalysisApp, CWinApp)
//{{AFX_MSG_MAP(CProtocolAnalysisApp)
//}}AFX_MSG_MAP
ON_COMMAND(ID_HELP, CWinApp::OnHelp)END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CProtocolAnalysisApp construction
CProtocolAnalysisApp::CProtocolAnalysisApp()
{
	// TODO: add construction code here,
	// Place all significant initialization in InitInstance
}

/////////////////////////////////////////////////////////////////////////////
// The one and only CProtocolAnalysisApp object

CProtocolAnalysisApp theApp;
CString g_lwtProgramName = _T("网络包截获分析系统(王丹)");//程序名称
HANDLE g_ProgramValue = (HANDLE)1; //程序句柄 
BOOL CALLBACK EnumWndProc(HWND hwnd, LPARAM lParam)
{
	HANDLE h = GetProp(hwnd, g_lwtProgramName);
	if (h ==g_ProgramValue)
	{
		*(HWND *) lParam = hwnd;
		return false;
	}
	
	return true;
}
BOOL CProtocolAnalysisApp::InitInstance()
{
	AfxInitRichEdit();//切忌 使用RichEdit要在此处初始化
	HWND oldHWnd = NULL;
	EnumWindows(EnumWndProc, (LPARAM) & oldHWnd); 
	if (oldHWnd != NULL)
	{
		m_pMainWnd->MessageBox ("本程序已经在运行了！","网络包截获分析系统");
		::ShowWindow(oldHWnd, SW_SHOWNORMAL); 
		::SetForegroundWindow(oldHWnd); 
		return false; 
	}
	GetModuleFileName(NULL, lwtGlobal_FilePath, _MAX_PATH);
	//////////////////////////////////////////////////////////////////////////////////
	int Length;
	Length=strlen(lwtGlobal_FilePath);
	for(int i=Length-1;i>=0;i--)
	{
		char temp;
		temp=lwtGlobal_FilePath[i];
		if(temp!='\\')
		{
			continue ;
		}
		else
		{
			break ;
		}
	}
	for(int j=0;j<i;j++)
	{
		Global_FileDirectory[j]=lwtGlobal_FilePath[j];
	}
	/////////////////////////////////////////////////////////////////////////////	
	AfxEnableControlContainer();
	
	CoInitialize(NULL);
#ifdef _AFXDLL
	Enable3dControls(); // Call this when using MFC in a shared DLL
#else
	Enable3dControlsStatic(); // Call this when linking to MFC statically
#endif	
	

	// 添加程序启动时的动画窗口
	COpenScreenWnd* imageWnd = new COpenScreenWnd;  //建立一个新窗口对象
	imageWnd->CreatScreenWnd ();			//创建窗口
	imageWnd->CenterWindow ();				//在屏幕中央
	imageWnd->ShowWindow (SW_SHOW);			//显示窗口
	imageWnd->UpdateWindow();				//更新窗口，激活OnPait函数
	if (imageWnd != NULL)
	{
		imageWnd->SendMessage (WM_CLOSE); //关闭窗口
	}
	delete imageWnd;
	CProtocolAnalysisDlg dlg;
	m_pMainWnd = &dlg;
	int nResponse = dlg.DoModal();
	
	if (nResponse == IDOK)
	{
		// TODO: Place code here to handle when the dialog is
		//  dismissed with OK
	}
	else if (nResponse == IDCANCEL)
	{
		// TODO: Place code here to handle when the dialog is
		//  dismissed with Cancel
	}
	
	// Since the dialog has been closed, return FALSE so that we exit the
	//  application, rather than start the application's message pump.
	return FALSE;
}
int CProtocolAnalysisApp::ExitInstance()
{
	// TODO: Add your specialized code here and/or call the base class
	return CWinApp::ExitInstance();
}
