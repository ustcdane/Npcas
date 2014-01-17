
#if !defined(AFX_ProtocolAnalysisDLG_H__9F879FF2_E47F_45D0_A1F8_029396B03303__INCLUDED_)
#define AFX_ProtocolAnalysisDLG_H__9F879FF2_E47F_45D0_A1F8_029396B03303__INCLUDED_

#if _MSC_VER > 1000
#pragma once 
#endif // _MSC_VER > 1000
//自定义消息
#define WM_MY_MESSAGE_COMMON (WM_USER+100) //显示数据包一些常用的消息
#define WM_MY_MESSAGE_ARP (WM_USER+101) //ARP/RARP
#define WM_MY_MESSAGE_IP (WM_USER+102) //IP
#define WM_MY_MESSAGE_TCP (WM_USER+103) //TCP
#define WM_MY_MESSAGE_UDP (WM_USER+104) //UDP
#define WM_MY_MESSAGE_ICMP  (WM_USER+105) //ICMP
#define WM_MY_MESSAGE_ETHERNET  (WM_USER+106)//ETHERNET
#define WM_MY_MESSAGE_HTTP (WM_USER+107) //HTTP
#define WM_MY_MESSAGE_DNS  (WM_USER+108) //DNS
#define WM_TRAYICON_MSG (WM_USER+109) //托盘
#include "stdafx.h"
#include "resource.h"
#include "sniffer.h"
#include "pcap.h"
class CProtocolAnalysisDlg : public CDialog
{
	
	// Construction
public:
	void ShowPacketInfo(RAW_PACKET* pRawPacket);//显示包信息
	bool m_SaveDumpFile;// 是否保存捕获到数据包的堆文件
	CString m_strfileNamePath; // 需要保存的文件路径(包括文件名)
	CString m_strFilePath;//需要保存的文件路径
	CProtocolAnalysisDlg(CWnd* pParent = NULL);	
	void DrawTitleBar(CDC* pDC);
	// 任务托盘
	LRESULT OnTrayCallBackMsg(WPARAM wparam, LPARAM lparam);
	NOTIFYICONDATA m_Ntnd;//任务托盘有关结构
	// 托盘 默认托盘
	bool TrayMyIcon(bool bAdd=true);
	// Dialog Data
	//{{AFX_DATA(CProtocolAnalysisDlg)
	enum { IDD = IDD_ProtocolAnalysis_DIALOG };
	CListCtrl	* m_pCurrentList;//标记当前选择的列表
	//关联到相应的控件变量
	CStatic	m_picCtrl;
	CStatic	 m_protocol_number;
	CListCtrl	m_list_Dns;
	CRichEditCtrl	m_EditCtrl;
	CListCtrl	m_list_http;
	CTreeCtrl	m_tree;
	CListCtrl	m_list_ethernet;
	CListCtrl	m_list_icmp;
	CListCtrl	m_list_udp;
	CListCtrl	m_list_tcp;
	CListCtrl	m_list_ip;
	CListCtrl	m_list_arp;
	CTabCtrl	m_tab1;
	CListCtrl	m_list_common;
	//}}AFX_DATA
	
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CProtocolAnalysisDlg)
protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support
	virtual LRESULT DefWindowProc(UINT message, WPARAM wParam, LPARAM lParam);
	//}}AFX_VIRTUAL
	
	// Implementation
protected:
	void ReleaseAll();//释放申请的内存
	void ShowIcmpInfo(int nItem);//显示 Icmp包信息
	void ShowArpInfo(int nItem);//显示 Arp包信息
	void ShowTcpInfo(int nItem);//显示 Tcp包信息
	void ShowUdpInfo( int nItem);//显示 Udp包信息
	void ShowIpInfo(int n); //显示 Ip包信息
	void ProcessRClickList();
	// 字体及颜色设置
	CHARFORMAT m_cf;
	int m_nPacket;//捕获的网路数据包计数
	int m_nArp;//记录捕获到的Arp包个数 
	int m_nIp;//记录捕获到的IP包个数 
	int m_Ethernet;//记录捕获到的以太帧个数 
	int m_nTcp;//记录捕获到的TCP包个数 
	int m_nUdp;//记录捕获到的UDP包个数 
	int m_nIcmp;//记录捕获到的ICMP包个数 
	int m_nHttp;//记录捕获到的HTTP包个数 
	int m_nDns;//记录捕获到的DNS包个数 
	int m_nItem;//记录当前右键选中的行号
	int m_iSubItem;//记录当前右键选中的列号
	HTREEITEM m_TreeRoot;//数控件根节点
	HTREEITEM m_MacHdrRoot;//Mac根节点
	HTREEITEM m_IpHdrRoot;//Ip根节点
	HTREEITEM m_UdpHdrRoot;//Udp根节点
	HTREEITEM m_TcpHdrRoot;//tcp根节点
	HTREEITEM m_IcmpHdrRoot;//Icmp根节点
	HTREEITEM m_ArpHdrRoot;//Arp根节点
	CImageList m_ImageList;
	HICON m_hIcon;
	CMenu* m_Psubmenu;
	CWinThread* m_pThread;
	// Generated message map functions
	//{{AFX_MSG(CProtocolAnalysisDlg)
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	afx_msg void OnButtonStart();
	afx_msg void OnButtonStop();
	afx_msg LRESULT  OnPacket(WPARAM wParam, LPARAM lParam);//
	afx_msg LRESULT  OnArp(WPARAM wParam, LPARAM lParam);
	afx_msg LRESULT  OnIp(WPARAM wParam, LPARAM lParam);
	afx_msg LRESULT  OnTcp(WPARAM wParam, LPARAM lParam);
	afx_msg LRESULT  OnUdp(WPARAM wParam, LPARAM lParam);
	afx_msg LRESULT  OnIcmp(WPARAM wParam, LPARAM lParam);
	afx_msg LRESULT  OnEthernet(WPARAM wParam, LPARAM lParam);
	afx_msg LRESULT  OnHttp(WPARAM wParam, LPARAM lParam);
	afx_msg LRESULT  OnDns(WPARAM wParam, LPARAM lParam);
	afx_msg void OnSelchangeTab1(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnStart();
	afx_msg void OnStop();
	afx_msg void OnExit();
	afx_msg void OnSetFileter();
	afx_msg void OnDrawItem(int nIDCtl, LPDRAWITEMSTRUCT lpDrawItemStruct);
	afx_msg void OnMeasureItem(int nIDCtl, LPMEASUREITEMSTRUCT lpMeasureItemStruct);
	afx_msg void OnRButtonUp(UINT nFlags, CPoint point);
	afx_msg void OnLButtonDown(UINT nFlags, CPoint point);
	afx_msg void OnMouseMove(UINT nFlags, CPoint point);
	afx_msg void OnLButtonUp(UINT nFlags, CPoint point);
	afx_msg void OnSize(UINT nType, int cx, int cy);
	afx_msg void OnClickTab1(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnMenuOpenDumpFile();
	afx_msg void OnMenuhelp();
	afx_msg void OnButtonOpenDumpFile();
	afx_msg void OnButtonSetFilter();
	afx_msg void OnSave();
	afx_msg int OnCreate(LPCREATESTRUCT lpCreateStruct);
	afx_msg void OnCancelMode();
	afx_msg void OnClickListCom(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnClickListUdp(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnClickListTcp(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnClickListIp(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnClickListArp(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnClickListEthernet(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnBtclear();
	afx_msg void OnRestart();
	afx_msg void OnmenuFirst();
	afx_msg void OnmenuLast();
	afx_msg void OnmenuCenter();
	afx_msg void OnMenuShow();
	afx_msg void OnMenuQuit();
	afx_msg void OnIfSave();
	afx_msg void OnClickListHttp(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnClickListIcmp(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnRclickListCom(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnCopy();
	afx_msg void OnRclickListPppoe(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnRclickListIp(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnRclickListArp(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnRclickListIcmp(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnRclickListTcp(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnRclickListUdp(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnRclickListHttp(NMHDR* pNMHDR, LRESULT* pResult);;
	afx_msg void OnSkin();
	afx_msg void OnSkin1();
	afx_msg void OnSkin2();
	afx_msg void OnSkin3();
	afx_msg void OnSkin4();
	afx_msg void OnSkinRe();
	afx_msg void OnDblclkTree(NMHDR* pNMHDR, LRESULT* pResult);//处理双击树节点
	afx_msg void OnClickListDns(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnRclickListDns(NMHDR* pNMHDR, LRESULT* pResult);
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};
//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.
#endif // !defined(AFX_ProtocolAnalysisDLG_H__9F879FF2_E47F_45D0_A1F8_029396B03303__INCLUDED_)
