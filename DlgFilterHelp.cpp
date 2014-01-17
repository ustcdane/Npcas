// DlgFilterHelp.cpp : implementation file
//

#include "stdafx.h"
#include "protocolanalysis.h"
#include "DlgFilterHelp.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// CDlgFilterHelp dialog
CDlgFilterHelp::CDlgFilterHelp(CWnd* pParent /*=NULL*/)
	: CDialog(CDlgFilterHelp::IDD, pParent)
{
	//{{AFX_DATA_INIT(CDlgFilterHelp)
		// NOTE: the ClassWizard will add member initialization here
	//}}AFX_DATA_INIT
}
void CDlgFilterHelp::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CDlgFilterHelp)
	DDX_Control(pDX, IDC_RICHEDIT_HELP, m_EditHelp);
	//}}AFX_DATA_MAP
}


BEGIN_MESSAGE_MAP(CDlgFilterHelp, CDialog)
	//{{AFX_MSG_MAP(CDlgFilterHelp)
	ON_WM_MOUSEMOVE()
	ON_WM_LBUTTONDOWN()
	ON_WM_CTLCOLOR()
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CDlgFilterHelp message handlers

BOOL CDlgFilterHelp::OnInitDialog() 
{
	CDialog::OnInitDialog();
	
	// TODO: Add extra initialization here
	CHARFORMAT cf;
	//�༭�ؼ�
		//��ʼ�����弰��ɫ
	ZeroMemory(&cf, sizeof(CHARFORMAT));
	cf.cbSize = sizeof(CHARFORMAT);
	cf.dwMask = CFM_BOLD | CFM_COLOR | CFM_FACE |
		CFM_ITALIC | CFM_SIZE | CFM_UNDERLINE;
	cf.dwEffects = 0;
	cf.yHeight = 16*15;//���ָ߶�
	cf.crTextColor = RGB(20, 30, 120); //������ɫ
	strcpy(cf.szFaceName ,_T("����"));//��������
	m_EditHelp.SetDefaultCharFormat(cf);
	CString str;
	str  = _T("1,������ڳ��ù��˹�����ѡ����˹�����,�·��ı༭����ʾ\r\n");
	str += _T("�������,������޸Ĵ˹�����䲢������Ӧ����İ�����\r\n");
	str += _T("2,��������·��ı༭��(���˹�����,�������)�����Լ��ĳ���\r\n");
	str += _T("�Ĺ��˹���,�������󷽵ı༭���е���Ӱ�ť,����Լ��Ĺ���\r\n");
	str += _T("���·��ı༭��Ϊ��ʱ,������ʱnew,newΪ����ӵ����ݡ�\r\n");
	str += _T("3,��ѡ��һ��ù��������Ժ󲻳���ʱ,����Ե������Ϸ���\r\n");
	str += _T("ɾ����ťɾ�����\r\n\r\n");
	str += _T("---------------------------------------------------------\r\n");
	str += _T("4,���˱��ʽ�Ļ������Ԫ��Ϊ�ؼ���,�����ʽ��һ��������\r\n");
	str += _T("�������,����֮��ͨ��and��or��not���ӡ��ؼ�����Ҫ�����ࣺ\r\n");
	str += _T("��һ�� �������ݰ�Դ��Ŀ�ĵصĹؼ���.�ؼ���host,net��port��\r\n");
	str += _T("��ָ�������ա�����IP��ַ������������,�����ַ�Ͷ˿ںŽ���\r\n");
	str += _T("�ж�,��δָ��,��Ĭ��Ϊhost;�ؼ���ǰ�������δ�dst,src��dst\r\n");
	str += _T("or srcָ�������ض����������,��δָ��,��Ĭ��Ϊdst or src��\r\n");
    str += _T("��\"dst host 210.31.234.254\",\"port 80\",\"src 210.31.234.13\"��\r\n"); 
	str += _T("�ڶ��� �������ݰ�Э�����͵Ĺؼ���.�ؼ���ether��fddi��tr��ip\r\n");
	str += _T("��ip6��arp��rarp��tcp��udp�ֱ�ָ��������·��,�����ʹ���\r\n");
	str += _T("������Э������.IP�������͵�ip proto��.�硰ether proto \\a\r\nrp����");
	str += _T("��,��ip proto \\tcp����\r\n");
	m_EditHelp.SetWindowText(str);
	//����̬�ı�����Ļ��������m_pRectLink��    
     GetDlgItem(IDC_LINK) -> GetWindowRect(&m_pRectLink);    
    //����Ļ����ת��Ϊ�ͻ�����    
     ScreenToClient(&m_pRectLink); 
	 m_font.CreatePointFont(120,"�����п�");
	return TRUE;  // return TRUE unless you set the focus to a control
	              // EXCEPTION: OCX Property Pages should return FALSE
}

void CDlgFilterHelp::OnMouseMove(UINT nFlags, CPoint point) 
{
	// TODO: Add your message handler code here and/or call default
	   //������������ھ�̬�ı���ʱ����������С��״    
    if (point.x > m_pRectLink.left && point.x < m_pRectLink.right && point.y > m_pRectLink.top && point.y < m_pRectLink.bottom )    
    //�˴�����ж������㷨    
     {    
        HCURSOR hCursor;    
         hCursor = AfxGetApp()->LoadStandardCursor(IDC_HAND);    
        //�������ΪС��״    
         SetCursor(hCursor);    
     }    
 
	CDialog::OnMouseMove(nFlags, point);
}

void CDlgFilterHelp::OnLButtonDown(UINT nFlags, CPoint point) 
{
	// TODO: Add your message handler code here and/or call default
	//�˴�����ж������㷨    
    if (point.x > m_pRectLink.left && point.x < m_pRectLink.right && point.y > m_pRectLink.top && point.y < m_pRectLink.bottom)    
	{    
        //����������    
        if (nFlags == MK_LBUTTON)       
		{    
            //Ϊ�������Ч�����˴��������ϱ任�����״�Ĵ���    
			ShellExecute(0, NULL, _T("http://blog.csdn.net/gfsfg8545/article/details/7490944"),
				NULL,NULL, SW_NORMAL);        
		}    
	}    
	CDialog::OnLButtonDown(nFlags, point);
}

HBRUSH CDlgFilterHelp::OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor) 
{
	HBRUSH hbr = CDialog::OnCtlColor(pDC, pWnd, nCtlColor);
	
	// TODO: Change any attributes of the DC here
	if (pWnd->GetDlgCtrlID()==IDC_LINK)
	{
		pDC->SetBkMode(TRANSPARENT);
		pDC->SetTextColor(RGB(0,255,0));  //����������ɫ
		pDC->SelectObject(&m_font);
		HBRUSH   temp=CreateSolidBrush(RGB(255,255,255));
		// TODO: Return a different brush if the default is not desired
		return temp;  
	}
	// TODO: Return a different brush if the default is not desired
	return hbr;
}
