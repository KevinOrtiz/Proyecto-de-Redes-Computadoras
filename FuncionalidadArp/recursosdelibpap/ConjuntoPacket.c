#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#define SIZE 2048

void mycallback(u_char *useless, const struct pcap_pkthdr* pkthdr, const u_char* packet)
    {
  static int count = 1;
  fprintf(stdout,"%d, ",count);
  fflush(stdout);
  count++;
}

int main(int argc , char **argv){
   
  char *dev;
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* descr;
    //bpf_u_int32 maskp;
    //bpf_u_int32 netp;
  dev="wlan0";
  if(dev==NULL){
    fprintf(stderr,"%s \n",errbuf);
    exit(1);
  }else{
    printf("Abriendo %s en modo promiscuo \n",dev);
  }

  if( (descr=pcap_open_live(dev,SIZE,-1,1000,errbuf) )==NULL){
    printf("Error");  
    return 0;
  }

  int num=200;
  pcap_loop(descr,num,mycallback,NULL);

     
  return 0;
}
