#if !defined(AFX_DLGFILTERHELP_H__E63465D5_E009_4727_A4A1_268AD950F6E4__INCLUDED_)
#define AFX_DLGFILTERHELP_H__E63465D5_E009_4727_A4A1_268AD950F6E4__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000
// DlgFilterHelp.h : header file
//

/////////////////////////////////////////////////////////////////////////////
// CDlgFilterHelp dialog

class CDlgFilterHelp : public CDialog
{
// Construction
public:
	CDlgFilterHelp(CWnd* pParent = NULL);   // standard constructor

// Dialog Data
	//{{AFX_DATA(CDlgFilterHelp)
	enum { IDD = IDD_DIALOG_HELP };
	CRichEditCtrl	m_EditHelp;
	//}}AFX_DATA


// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CDlgFilterHelp)
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:
	//用于保存超链接静态文本框的屏幕坐标 
	RECT m_pRectLink;
    CFont m_font;
	// Generated message map functions
	//{{AFX_MSG(CDlgFilterHelp)
	virtual BOOL OnInitDialog();
	afx_msg void OnMouseMove(UINT nFlags, CPoint point);
	afx_msg void OnLButtonDown(UINT nFlags, CPoint point);
	afx_msg HBRUSH OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor);
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_DLGFILTERHELP_H__E63465D5_E009_4727_A4A1_268AD950F6E4__INCLUDED_)
