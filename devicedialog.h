#if !defined(AFX_DEVICEDIALOG_H__8BD28462_03FC_42DD_B4E4_64C86C0B4DCC__INCLUDED_)
#define AFX_DEVICEDIALOG_H__8BD28462_03FC_42DD_B4E4_64C86C0B4DCC__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000
// DeviceDialog.h : header file
//

/////////////////////////////////////////////////////////////////////////////
// CDeviceDialog dialog

class CDeviceDialog : public CDialog
{
// Construction
public:
	CDeviceDialog(CWnd* pParent = NULL);   // standard constructor

// Dialog Data
	//{{AFX_DATA(CDeviceDialog)
	enum { IDD = IDD_DIALOG_DEVICE };
	CListBox	m_list_device;
	//}}AFX_DATA


// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CDeviceDialog)
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:

	// Generated message map functions
	//{{AFX_MSG(CDeviceDialog)
	virtual BOOL OnInitDialog();
	virtual void OnOK();
	afx_msg HBRUSH OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor);
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_DEVICEDIALOG_H__8BD28462_03FC_42DD_B4E4_64C86C0B4DCC__INCLUDED_)
