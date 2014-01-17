
#if !defined(AFX_MYDIALOG_H__FE67E2FF_56CF_463A_B83D_192DD7C40283__INCLUDED_)
#define AFX_MYDIALOG_H__FE67E2FF_56CF_463A_B83D_192DD7C40283__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000


/////////////////////////////////////////////////////////////////////////////
// helpdialog dialog

class Chelpdialog : public CDialog
{
	// Construction
public:
	Chelpdialog(CWnd* pParent = NULL);   // standard constructor

	// Dialog Data
	//{{AFX_DATA(Chelpdialog) 
	enum { IDD = IDD_DIALOG_F1 };
	//}}AFX_DATA

	// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(Chelpdialog)
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support
	//}}AFX_VIRTUAL

	// Implementation
protected:
	// Generated message map functions
	//{{AFX_MSG(Chelpdialog)
	virtual void OnOK();
	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	afx_msg void OnLButtonDown(UINT nFlags, CPoint point);
	afx_msg void OnMouseMove(UINT nFlags, CPoint point);
	afx_msg void OnCancelMode();
	afx_msg HBRUSH OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor);
	afx_msg void OnCaptureChanged(CWnd *pWnd);
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
	//用于保存超链接静态文本框的屏幕坐标 
	RECT m_pRectLink;
};

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_MYDIALOG_H__FE67E2FF_56CF_463A_B83D_192DD7C40283__INCLUDED_)
