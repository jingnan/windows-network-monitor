// mcf6.h : PROJECT_NAME Ӧ�ó������ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"		// ������


// Cmcf6App:
class Cmcf6App : public CWinApp
{
public:
	Cmcf6App();
	public:
	virtual BOOL InitInstance();
	DECLARE_MESSAGE_MAP()
};

extern Cmcf6App theApp;