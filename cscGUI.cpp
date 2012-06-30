/*�������ICMP��UDP��TCP*/
		if(1 == local_data->iph->proto )							//ICMP
		{
			HTREEITEM icmp = this->m_treeCtrl.InsertItem(_T("ICMPЭ��ͷ"),data);

			str.Format(_T("����:%d"),local_data->icmph->type);
			this->m_treeCtrl.InsertItem(str,icmp);
			str.Format(_T("����:%d"),local_data->icmph->code);
			this->m_treeCtrl.InsertItem(str,icmp);
			str.Format(_T("���:%d"),local_data->icmph->seq);
			this->m_treeCtrl.InsertItem(str,icmp);
			str.Format(_T("У���:%d"),local_data->icmph->chksum);
			this->m_treeCtrl.InsertItem(str,icmp);

		}else if(6 == local_data->iph->proto){				//TCP

			HTREEITEM tcp = this->m_treeCtrl.InsertItem(_T("TCPЭ��ͷ"),data);

			str.Format(_T("  Դ�˿�:%d"),local_data->tcph->sport);
			this->m_treeCtrl.InsertItem(str,tcp);
			str.Format(_T("  Ŀ�Ķ˿�:%d"),local_data->tcph->dport);
			this->m_treeCtrl.InsertItem(str,tcp);
			str.Format(_T("  ���к�:0x%02x"),local_data->tcph->seq);
			this->m_treeCtrl.InsertItem(str,tcp);
			str.Format(_T("  ȷ�Ϻ�:%d"),local_data->tcph->ack_seq);
			this->m_treeCtrl.InsertItem(str,tcp);
			str.Format(_T("  ͷ������:%d"),local_data->tcph->doff);

			HTREEITEM flag = this->m_treeCtrl.InsertItem(_T(" +��־λ"),tcp);

			str.Format(_T("cwr %d"),local_data->tcph->cwr);
			this->m_treeCtrl.InsertItem(str,flag);
			str.Format(_T("ece %d"),local_data->tcph->ece);
			this->m_treeCtrl.InsertItem(str,flag);
			str.Format(_T("urg %d"),local_data->tcph->urg);
			this->m_treeCtrl.InsertItem(str,flag);
			str.Format(_T("ack %d"),local_data->tcph->ack);
			this->m_treeCtrl.InsertItem(str,flag);
			str.Format(_T("psh %d"),local_data->tcph->psh);
			this->m_treeCtrl.InsertItem(str,flag);
			str.Format(_T("rst %d"),local_data->tcph->rst);
			this->m_treeCtrl.InsertItem(str,flag);
			str.Format(_T("syn %d"),local_data->tcph->syn);
			this->m_treeCtrl.InsertItem(str,flag);
			str.Format(_T("fin %d"),local_data->tcph->fin);
			this->m_treeCtrl.InsertItem(str,flag);

			str.Format(_T("  ����ָ��:%d"),local_data->tcph->urg_ptr);
			this->m_treeCtrl.InsertItem(str,tcp);
			str.Format(_T("  У���:0x%02x"),local_data->tcph->check);
			this->m_treeCtrl.InsertItem(str,tcp);
			str.Format(_T("  ѡ��:%d"),local_data->tcph->opt);
			this->m_treeCtrl.InsertItem(str,tcp);
		}else if(17 == local_data->iph->proto){				//UDP
			HTREEITEM udp = this->m_treeCtrl.InsertItem(_T("UDPЭ��ͷ"),data);

			str.Format(_T("Դ�˿�:%d"),local_data->udph->sport);
			this->m_treeCtrl.InsertItem(str,udp);
			str.Format(_T("Ŀ�Ķ˿�:%d"),local_data->udph->dport);
			this->m_treeCtrl.InsertItem(str,udp);
			str.Format(_T("�ܳ���:%d"),local_data->udph->len);
			this->m_treeCtrl.InsertItem(str,udp);
			str.Format(_T("У���:0x%02x"),local_data->udph->check);
			this->m_treeCtrl.InsertItem(str,udp);
		}
	}else if(0x86dd == local_data->ethh->type){		//IPv6
		HTREEITEM ip6 = this->m_treeCtrl.InsertItem(_T("IPv6Э��ͷ"),data);
		str.Format(_T("�汾:%d"),local_data->iph6->flowtype);
		this->m_treeCtrl.InsertItem(str,ip6);
		str.Format(_T("������:%d"),local_data->iph6->version);
		this->m_treeCtrl.InsertItem(str,ip6);
		str.Format(_T("����ǩ:%d"),local_data->iph6->flowid);
		this->m_treeCtrl.InsertItem(str,ip6);
		str.Format(_T("��Ч�غɳ���:%d"),local_data->iph6->plen);
		this->m_treeCtrl.InsertItem(str,ip6);
		str.Format(_T("��һ���ײ�:0x%02x"),local_data->iph6->nh);
		this->m_treeCtrl.InsertItem(str,ip6);
		str.Format(_T("������:%d"),local_data->iph6->hlim);
		this->m_treeCtrl.InsertItem(str,ip6);

		str.Format(_T("Դ��ַ:"));
		int n;
		for(n=0;n<8;n++)
		{
			if(n<=6)
				str.AppendFormat(_T("%02x:"),local_data->iph6->saddr[n]);
			else
				str.AppendFormat(_T("%02x"),local_data->iph6->saddr[n]);
		}
		this->m_treeCtrl.InsertItem(str,ip6);

		str.Format(_T("Ŀ�ĵ�ַ:"));
		for(n=0;n<8;n++)
		{
			if(n<=6)
				str.AppendFormat(_T("%02x:"),local_data->iph6->saddr[n]);
			else
				str.AppendFormat(_T("%02x"),local_data->iph6->saddr[n]);
		}
		this->m_treeCtrl.InsertItem(str,ip6);
