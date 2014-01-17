
#if !defined(AFX_ProtocolAnalysisDLG_H__9F879FF2_E47F_45D0_A1F8_029396B03303__INCLUDED_)
#define AFX_ProtocolAnalysisDLG_H__9F879FF2_E47F_45D0_A1F8_029396B03303__INCLUDED_

#if _MSC_VER > 1000
#pragma once 
#endif // _MSC_VER > 1000
//�Զ�����Ϣ
#define WM_MY_MESSAGE_COMMON (WM_USER+100) //��ʾ���ݰ�һЩ���õ���Ϣ
#define WM_MY_MESSAGE_ARP (WM_USER+101) //ARP/RARP
#define WM_MY_MESSAGE_IP (WM_USER+102) //IP
#define WM_MY_MESSAGE_TCP (WM_USER+103) //TCP
#define WM_MY_MESSAGE_UDP (WM_USER+104) //UDP
#define WM_MY_MESSAGE_ICMP  (WM_USER+105) //ICMP
#define WM_MY_MESSAGE_ETHERNET  (WM_USER+106)//ETHERNET
#define WM_MY_MESSAGE_HTTP (WM_USER+107) //HTTP
#define WM_MY_MESSAGE_DNS  (WM_USER+108) //DNS
#define WM_TRAYICON_MSG (WM_USER+109) //����
#include "stdafx.h"
#include "resource.h"
#include "sniffer.h"
#include "pcap.h"
class CProtocolAnalysisDlg : public CDialog
{
	
	// Construction
public:
	void ShowPacketInfo(RAW_PACKET* pRawPacket);//��ʾ����Ϣ
	bool m_SaveDumpFile;// �Ƿ񱣴沶�����ݰ��Ķ��ļ�
	CString m_strfileNamePath; // ��Ҫ������ļ�·��(�����ļ���)
	CString m_strFilePath;//��Ҫ������ļ�·��
	CProtocolAnalysisDlg(CWnd* pParent = NULL);	
	void DrawTitleBar(CDC* pDC);
	// ��������
	LRESULT OnTrayCallBackMsg(WPARAM wparam, LPARAM lparam);
	NOTIFYICONDATA m_Ntnd;//���������йؽṹ
	// ���� Ĭ������
	bool TrayMyIcon(bool bAdd=true);
	// Dialog Data
	//{{AFX_DATA(CProtocolAnalysisDlg)
	enum { IDD = IDD_ProtocolAnalysis_DIALOG };
	CListCtrl	* m_pCurrentList;//��ǵ�ǰѡ����б�
	//��������Ӧ�Ŀؼ�����
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
	void ReleaseAll();//�ͷ�������ڴ�
	void ShowIcmpInfo(int nItem);//��ʾ Icmp����Ϣ
	void ShowArpInfo(int nItem);//��ʾ Arp����Ϣ
	void ShowTcpInfo(int nItem);//��ʾ Tcp����Ϣ
	void ShowUdpInfo( int nItem);//��ʾ Udp����Ϣ
	void ShowIpInfo(int n); //��ʾ Ip����Ϣ
	void ProcessRClickList();
	// ���弰��ɫ����
	CHARFORMAT m_cf;
	int m_nPacket;//�������·���ݰ�����
	int m_nArp;//��¼���񵽵�Arp������ 
	int m_nIp;//��¼���񵽵�IP������ 
	int m_Ethernet;//��¼���񵽵���̫֡���� 
	int m_nTcp;//��¼���񵽵�TCP������ 
	int m_nUdp;//��¼���񵽵�UDP������ 
	int m_nIcmp;//��¼���񵽵�ICMP������ 
	int m_nHttp;//��¼���񵽵�HTTP������ 
	int m_nDns;//��¼���񵽵�DNS������ 
	int m_nItem;//��¼��ǰ�Ҽ�ѡ�е��к�
	int m_iSubItem;//��¼��ǰ�Ҽ�ѡ�е��к�
	HTREEITEM m_TreeRoot;//���ؼ����ڵ�
	HTREEITEM m_MacHdrRoot;//Mac���ڵ�
	HTREEITEM m_IpHdrRoot;//Ip���ڵ�
	HTREEITEM m_UdpHdrRoot;//Udp���ڵ�
	HTREEITEM m_TcpHdrRoot;//tcp���ڵ�
	HTREEITEM m_IcmpHdrRoot;//Icmp���ڵ�
	HTREEITEM m_ArpHdrRoot;//Arp���ڵ�
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
	afx_msg void OnDblclkTree(NMHDR* pNMHDR, LRESULT* pResult);//����˫�����ڵ�
	afx_msg void OnClickListDns(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnRclickListDns(NMHDR* pNMHDR, LRESULT* pResult);
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};
//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.
#endif // !defined(AFX_ProtocolAnalysisDLG_H__9F879FF2_E47F_45D0_A1F8_029396B03303__INCLUDED_)
