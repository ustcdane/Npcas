#if !defined(AFX_OPENSCREENWND_H__CBEF76BC_69FB_4A39_93B5_827FE45B8CE5__INCLUDED_)
#define AFX_OPENSCREENWND_H__CBEF76BC_69FB_4A39_93B5_827FE45B8CE5__INCLUDED_
//////////////////////////////////////////////////////////////////////////////
//	程序开启时的动态显示窗口类
// COpenScreenWnd
//////////////////////////////////////////////////////////////////////////////
#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000
#include "resource.h"
/////////////////////////////////////////////////////////////////////////////
// COpenScreenWnd window

class COpenScreenWnd : public CWnd
{
// Construction
public:
	COpenScreenWnd();

// Attributes
public:
	CDC m_MemDC;  // 创建内存DC
	BITMAP m_bm;  // 创建位图结构变量
	CBitmap m_bitmap;  // 创建位图对象
    CBitmap *old_bitmap;  // 创建位图对象指针
	void CreatScreenWnd(); // 创建窗口
	

// Operations
public:

// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(COpenScreenWnd)
	//}}AFX_VIRTUAL

// Implementation
public:
	virtual ~COpenScreenWnd();// 析构函数

	// Generated message map functions
protected:
	//{{AFX_MSG(COpenScreenWnd)
	afx_msg void OnPaint();
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};

/////////////////////////////////////////////////////////////////////////////

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_OPENSCREENWND_H__CBEF76BC_69FB_4A39_93B5_827FE45B8CE5__INCLUDED_)
