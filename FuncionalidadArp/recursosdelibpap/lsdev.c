#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap.h>

///Este programa lo que hace es detectar los dispositivos de red connectados
int main( int argc , char **argv)
{
  char *net;
  char *mask;
  char *dev;
  int ret;
  char errbuf[PCAP_ERRBUF_SIZE];
  bpf_u_int32 netp;
  bpf_u_int32 maskp;
  struct in_addr addr;
  
    if((dev=pcap_lookupdev(errbuf))==NULL) //se muestras las interfaces libres
    {
      printf("ERROR %s \n ",errbuf);
      exit(-1);
    }

  //Se muestra el nombre del dispositivo
    printf("NAME OF DEVISE : %s \n",dev);
   
  //Aqui queremos obtener la direccion de red y la mascara
  if((ret=pcap_lookupnet(dev,&netp,&maskp,errbuf))==-1)
   {
    printf("ERROR %s \n ",errbuf);
    exit(-1);
    }
   addr.s_addr=netp;
   
    if((net=inet_ntoa(addr))==NULL)
    {
    perror("inet_ntoa");
    exit(-1);
    }
   
    printf("Direccion de Red : %s \n",net);
    addr.s_addr=maskp;
    mask=inet_ntoa(addr);
    if((net=inet_ntoa(addr))==NULL)
    {
    perror("inet_ntoa");
    exit(-1);
    }
   printf("Mascara de Red %s \n",mask);
 return 0;
  }
