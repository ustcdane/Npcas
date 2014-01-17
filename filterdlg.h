#if !defined(AFX_FILTERDLG_H__8A158A85_7A74_4D82_8DC2_510685FBA62D__INCLUDED_)
#define AFX_FILTERDLG_H__8A158A85_7A74_4D82_8DC2_510685FBA62D__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000
// 过滤规则对话框
#include <string.h>
#include <vector> //STL头文件
using namespace std;
/////////////////////////////////////////////////////////////////////////////
// Cfilterdlg dialog
//过滤规则数据结构
typedef struct FILETER_   
	{
		char FilterName[256];    // 过滤规则名称
	    char FilterValue[256];   // 过滤规则语句表达式
	   // 重载赋值运算符
	   const FILETER_ & operator=( const FILETER_ temp )
	   {
		   ZeroMemory(FilterName,256);
		   ZeroMemory(FilterValue,256);
		   strcpy(FilterValue,temp.FilterValue);
		   strcpy(FilterName,temp.FilterName);  
		   return *this;
	   }
	}FILETER_DATA ,*PFILETER_DATA;
typedef vector<FILETER_DATA>  Filter_Vector;//文件链表结构定义

class Cfilterdlg : public CDialog
{
	// Construction
public:
	Cfilterdlg(CWnd* pParent = NULL);   // standard constructor

	// Dialog Data
	//{{AFX_DATA(Cfilterdlg)
	enum { IDD = IDD_FILTER_DLG };
	CListBox	m_FilterBox;
	CString	m_filter;
	CString	m_filterName;
	//}}AFX_DATA


	// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(Cfilterdlg)
	public:
	virtual BOOL DestroyWindow();
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support
	//}}AFX_VIRTUAL

	// Implementation
protected:
	void SaveUserFilter();
	void LoadUserFilter();
	CString m_strPath;
	Filter_Vector m_FilterList;
	// Generated message map functions
	//{{AFX_MSG(Cfilterdlg)
	virtual BOOL OnInitDialog();
	virtual void OnOK();
	afx_msg void OnSelchangeListFilter();
	afx_msg void OnBtDel();
	afx_msg void OnBtNew();
	afx_msg void OnBtHelp();
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_FILTERDLG_H__8A158A85_7A74_4D82_8DC2_510685FBA62D__INCLUDED_)
