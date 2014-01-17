# Microsoft Developer Studio Project File - Name="Npcas" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Application" 0x0101

CFG=Npcas - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "Npcas.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "Npcas.mak" CFG="Npcas - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "Npcas - Win32 Release" (based on "Win32 (x86) Application")
!MESSAGE "Npcas - Win32 Debug" (based on "Win32 (x86) Application")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "Npcas - Win32 Release"

# PROP BASE Use_MFC 6
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 5
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MD /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_AFXDLL" /Yu"stdafx.h" /FD /c
# ADD CPP /nologo /MT /W3 /GX /Zi /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /FR /Yu"stdafx.h" /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x804 /d "NDEBUG" /d "_AFXDLL"
# ADD RSC /l 0x804 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 /nologo /subsystem:windows /machine:I386
# ADD LINK32 wpcap.lib ws2_32.lib /nologo /subsystem:windows /debug /machine:I386

!ELSEIF  "$(CFG)" == "Npcas - Win32 Debug"

# PROP BASE Use_MFC 6
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 6
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MDd /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_AFXDLL" /Yu"stdafx.h" /FD /GZ /c
# ADD CPP /nologo /MDd /W3 /Gm /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_MBCS" /D "WPCAP" /D "_AFXDLL" /FR /FD /GZ /c
# SUBTRACT CPP /YX /Yc /Yu
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x804 /d "_DEBUG" /d "_AFXDLL"
# ADD RSC /l 0x804 /d "_DEBUG" /d "_AFXDLL"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 /nologo /subsystem:windows /debug /machine:I386 /pdbtype:sept
# ADD LINK32 wpcap.lib ws2_32.lib /nologo /subsystem:windows /debug /machine:I386 /pdbtype:sept

!ENDIF 

# Begin Target

# Name "Npcas - Win32 Release"
# Name "Npcas - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=.\DeviceDialog.cpp
# End Source File
# Begin Source File

SOURCE=.\DlgFilterHelp.cpp
# End Source File
# Begin Source File

SOURCE=.\filterdlg.cpp
# End Source File
# Begin Source File

SOURCE=.\helpdialog.cpp
# End Source File
# Begin Source File

SOURCE=.\OpenScreenWnd.cpp
# End Source File
# Begin Source File

SOURCE=.\Protocol.cpp
# End Source File
# Begin Source File

SOURCE=.\Protocolanalysis.cpp
# End Source File
# Begin Source File

SOURCE=.\ProtocolanalysisDlg.cpp
# End Source File
# Begin Source File

SOURCE=.\sniffer.cpp
# End Source File
# Begin Source File

SOURCE=.\sniffer.h
# End Source File
# Begin Source File

SOURCE=.\StdAfx.cpp
# ADD CPP /Yc"stdafx.h"
# End Source File
# Begin Source File

SOURCE=".\Npcas.rc"
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=.\DeviceDialog.h
# End Source File
# Begin Source File

SOURCE=.\DlgFilterHelp.h
# End Source File
# Begin Source File

SOURCE=.\filterdlg.h
# End Source File
# Begin Source File

SOURCE=.\helpdialog.h
# End Source File
# Begin Source File

SOURCE=.\OpenScreenWnd.h
# End Source File
# Begin Source File

SOURCE=.\Protocol.h
# End Source File
# Begin Source File

SOURCE=.\Protocolanalysis.h
# End Source File
# Begin Source File

SOURCE=.\ProtocolanalysisDlg.h
# End Source File
# Begin Source File

SOURCE=.\Resource.h
# End Source File
# Begin Source File

SOURCE=.\StdAfx.h
# End Source File
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter "ico;cur;bmp;dlg;rc2;rct;bin;rgs;gif;jpg;jpeg;jpe"
# Begin Source File

SOURCE=.\res\1.ico
# End Source File
# Begin Source File

SOURCE=.\res\20120418031703240_easyicon_cn_24.ico
# End Source File
# Begin Source File

SOURCE=.\res\20120418033051355_easyicon_cn_16.ico
# End Source File
# Begin Source File

SOURCE=.\res\20120418040922659_easyicon_cn_24.ico
# End Source File
# Begin Source File

SOURCE=.\res\20120418041543954_easyicon_cn_24.ico
# End Source File
# Begin Source File

SOURCE=.\res\213291_090043013_2.bmp
# End Source File
# Begin Source File

SOURCE=.\res\_piazico.ico
# End Source File
# Begin Source File

SOURCE=.\res\about.bmp
# End Source File
# Begin Source File

SOURCE=.\res\Analyzer.ico
# End Source File
# Begin Source File

SOURCE=.\res\de.bmp
# End Source File
# Begin Source File

SOURCE=.\res\dir.ico
# End Source File
# Begin Source File

SOURCE=".\res\GOAL!FIFAWorldCup2006086.ico"
# End Source File
# Begin Source File

SOURCE=.\res\icon.ico
# End Source File
# Begin Source File

SOURCE=.\res\icon8.ico
# End Source File
# Begin Source File

SOURCE=.\res\my.bmp
# End Source File
# Begin Source File

SOURCE=.\res\oper.ico
# End Source File
# Begin Source File

SOURCE=.\res\skin.ico
# End Source File
# Begin Source File

SOURCE=.\res\sr.ico
# End Source File
# Begin Source File

SOURCE=.\res\sum.ico
# End Source File
# Begin Source File

SOURCE=.\res\text.ico
# End Source File
# Begin Source File

SOURCE=".\res\Npcas.rc2"
# End Source File
# End Group
# Begin Source File

SOURCE=.\ReadMe.txt
# End Source File
# End Target
# End Project
# Section Npcas : {D27CDB6E-AE6D-11CF-96B8-444553540000}
# 	2:21:DefaultSinkHeaderFile:shockwaveflash.h
# 	2:16:DefaultSinkClass:CShockwaveFlash
# End Section
# Section Npcas : {D27CDB6C-AE6D-11CF-96B8-444553540000}
# 	2:5:Class:CShockwaveFlash
# 	2:10:HeaderFile:shockwaveflash.h
# 	2:8:ImplFile:shockwaveflash.cpp
# End Section
