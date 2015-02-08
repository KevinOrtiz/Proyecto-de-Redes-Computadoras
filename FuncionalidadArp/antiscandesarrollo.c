#include <pcap.h>
#include <stdio.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <time.h>

clock_t begintime;
clock_t finaltime;

int cont;

void antiscan(char *argc , char *argv)
{
	if(!strcmp("-t",argc))
	{
		
	}
}