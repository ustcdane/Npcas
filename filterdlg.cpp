 // Cfilterdlg.cpp : implementation file
//

#include "stdafx.h"
#include "resource.h"
#include "filterdlg.h"
#include "DlgFilterHelp.h"
#include "ProtocolanalysisDlg.h"
#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif
extern char g_PacketFilter[1024];
/////////////////////////////////////////////////////////////////////////////
// Cfilterdlg dialog

Cfilterdlg::Cfilterdlg(CWnd* pParent /*=NULL*/) : CDialog(Cfilterdlg::IDD, pParent)
{
	//{{AFX_DATA_INIT(Cfilterdlg)
	m_filter = _T("");
	m_filterName = _T("");
	//}}AFX_DATA_INIT
	
}


void Cfilterdlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(Cfilterdlg)
	DDX_Control(pDX, IDC_LIST_FILTER, m_FilterBox);
	DDX_Text(pDX, IDC_EDIT_FILTER, m_filter);
	DDX_Text(pDX, IDC_EDIT_FILTER_NAME, m_filterName);
	//}}AFX_DATA_MAP
	
}


BEGIN_MESSAGE_MAP(Cfilterdlg, CDialog)
//{{AFX_MSG_MAP(Cfilterdlg)
	ON_LBN_SELCHANGE(IDC_LIST_FILTER, OnSelchangeListFilter)
	ON_BN_CLICKED(IDC_BT_DEL, OnBtDel)
	ON_BN_CLICKED(IDC_BT_NEW, OnBtNew)
ON_WM_PAINT()
	ON_BN_CLICKED(IDC_BT_HELP, OnBtHelp)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// Cfilterdlg message handlers

BOOL Cfilterdlg::OnInitDialog()
{
	CDialog::OnInitDialog();
	CenterWindow(); 
	CProtocolAnalysisDlg *pDlg=(CProtocolAnalysisDlg *)GetParent();
	m_strPath=pDlg->m_strFilePath;
	m_strPath +="\\config\\filter.ini";
	LoadUserFilter();//加载用户自己的过滤规则库
	//设置删除按钮为 灰
	CButton *p=(CButton*)GetDlgItem (IDC_BT_DEL);
	p->EnableWindow (FALSE);
	m_filter=g_PacketFilter;//把先前的过滤规则显示出来
	UpdateData(FALSE);
	return TRUE;  // return TRUE unless you set the focus to a control
	// EXCEPTION: OCX Property Pages should return FALSE
}

void Cfilterdlg::OnOK()
{
	// TODO: Add extra validation here
	//	AnimateWindow(GetSafeHwnd(),1000,AW_HIDE|AW_BLEND);
	CDialog::OnOK();
}


void Cfilterdlg::LoadUserFilter()
{
	#define  TEMP_BUF_SIZE 256//缓冲区长度
	//从ini文件中获得规则数量
 	int count =::GetPrivateProfileInt("FilterCount", "Count", 0, m_strPath);
	if(count<=0)
		return;
	int nIndex = 0;
	while (TRUE)
	{
		CString strSection("section");
		CString strIndex;
		strIndex.Format("%d",nIndex);
		strSection += strIndex;
		FILETER_DATA temp;
		
		//过滤规则名字
		CString strSectionKey = "FilterName";					
		char cBuf[TEMP_BUF_SIZE];
		memset(cBuf, 0, TEMP_BUF_SIZE);
		if(GetPrivateProfileString (strSection, strSectionKey, NULL, cBuf, 
			TEMP_BUF_SIZE, m_strPath))
		{
			m_FilterBox.InsertString(nIndex,cBuf);
			strcpy(temp.FilterName,cBuf);
		}
		//规则语句
		strSectionKey = "FilterValue";
		memset(cBuf, 0, TEMP_BUF_SIZE);
		if(GetPrivateProfileString (strSection, strSectionKey, NULL, cBuf, 
			TEMP_BUF_SIZE, m_strPath))
		{
			strcpy(temp.FilterValue,cBuf);
		}
		m_FilterList.push_back(temp);
		if(++nIndex>=count) // 规则库加载完毕
			break;
	}
}

void Cfilterdlg::SaveUserFilter()
{
	if(m_FilterList.empty())//库列表为空时
		return;
	//删除原来的文件
	DeleteFile(m_strPath);
	int		nIndex = 0;
	//遍历整个链表
	for (Filter_Vector::iterator it = m_FilterList.begin(); it != m_FilterList.end(); ++it)
	{	
		FILETER_DATA da=(*it);
		CString strSection("section");							
		//section
		CString strIndex;
		strIndex.Format("%d",nIndex);
		strSection += strIndex;
		//写规则名称
		WritePrivateProfileString(strSection, _T("FilterName"), da.FilterName, m_strPath);		
		//规则语句
		WritePrivateProfileString(strSection, _T("FilterValue"),da.FilterValue,m_strPath);	
		++nIndex;
	}
	//将规则数量写入ini文件
	CString strCount;
	strCount.Format("%d", nIndex);
	::WritePrivateProfileString("FilterCount", "Count", strCount,m_strPath);	
	m_FilterList.clear();//删除链表所有节点
}


BOOL Cfilterdlg::DestroyWindow() 
{
	// TODO: Add your specialized code here and/or call the base class
	SaveUserFilter();
	return CDialog::DestroyWindow();
}

void Cfilterdlg::OnSelchangeListFilter() 
{
	// TODO: Add your control notification handler code here
	int nItem = m_FilterBox.GetCurSel();
	if(-1 == nItem)
		return;
	CString str;
	m_FilterBox.GetText(nItem,str);
	Filter_Vector::iterator it;
	for(it=m_FilterList.begin();it!=m_FilterList.end();it++)
	{
		if(str==FILETER_DATA(*it).FilterName)
		{
			m_filterName=(*it).FilterName;
			m_filter=(*it).FilterValue;
			break;
		}
	}
	CButton *p=(CButton*)GetDlgItem (IDC_BT_DEL);
	p->EnableWindow();
	UpdateData(FALSE);
}

void Cfilterdlg::OnBtDel() 
{
	// TODO: Add your control notification handler code here
	UpdateData();
	int nItem = m_FilterBox.GetCurSel();
	if (nItem==-1)
	{
		CButton *p=(CButton*)GetDlgItem (IDC_BT_DEL);
		p->EnableWindow (FALSE);
		return ;
	}
	Filter_Vector::iterator it;
	for(it=m_FilterList.begin();it!=m_FilterList.end();it++)
	{
		if(m_filterName==FILETER_DATA(*it).FilterName)
		{
			m_FilterList.erase(it);
			m_filterName =_T("");
			m_filter =_T("");
			m_FilterBox.DeleteString(nItem);
			UpdateData(FALSE);
			break;
		}
	}
	CButton *p=(CButton*)GetDlgItem (IDC_BT_DEL);
	p->EnableWindow (FALSE);
}

void Cfilterdlg::OnBtNew() 
{
	// TODO: Add your control notification handler code here
	UpdateData();
	int nItem = m_FilterBox.GetCurSel();
	FILETER_DATA da;
	if (m_filterName == _T(""))//表为空时
	{
		m_filterName =_T("new");
		m_filter =_T("new");
		strcpy(da.FilterName,m_filterName);
		strcpy(da.FilterValue,m_filter);
	}
	else
	{
		strcpy(da.FilterName,m_filterName);
		strcpy(da.FilterValue,m_filter);
	}
	m_FilterList.push_back(da);
	m_FilterBox.InsertString(m_FilterList.size()-1,m_filterName);
	UpdateData(FALSE);
}

void Cfilterdlg::OnBtHelp() 
{
	// TODO: Add your control notification handler code here
	CDlgFilterHelp dia;
	int result =dia.DoModal ();
	if (result==IDOK)
	{
	}
}
