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
CString g_lwtProgramName = _T("������ػ����ϵͳ(����)");//��������
HANDLE g_ProgramValue = (HANDLE)1; //������ 
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
	AfxInitRichEdit();//�м� ʹ��RichEditҪ�ڴ˴���ʼ��
	HWND oldHWnd = NULL;
	EnumWindows(EnumWndProc, (LPARAM) & oldHWnd); 
	if (oldHWnd != NULL)
	{
		m_pMainWnd->MessageBox ("�������Ѿ��������ˣ�","������ػ����ϵͳ");
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
	

	// ��ӳ�������ʱ�Ķ�������
	COpenScreenWnd* imageWnd = new COpenScreenWnd;  //����һ���´��ڶ���
	imageWnd->CreatScreenWnd ();			//��������
	imageWnd->CenterWindow ();				//����Ļ����
	imageWnd->ShowWindow (SW_SHOW);			//��ʾ����
	imageWnd->UpdateWindow();				//���´��ڣ�����OnPait����
	if (imageWnd != NULL)
	{
		imageWnd->SendMessage (WM_CLOSE); //�رմ���
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
