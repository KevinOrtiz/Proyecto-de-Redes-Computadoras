#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
  int main(int argc, char **argv)
   
   {
      int i;
      char *dev;
      char errbuf[PCAP_ERRBUF_SIZE];
      pcap_t *descr;
      const u_char *packet;
      struct pcap_pkthdr hdr;
      u_char *ptr;

        if ((dev=pcap_lookupdev(errbuf))==NULL)
        {
        printf("%s \n",errbuf);
        exit(-1);
        }
         printf("Abriendo DISPOSITIVO %s \n",dev);

        if (( descr=pcap_open_live(dev,BUFSIZ,0,-1,errbuf))==NULL)
        {
         printf("pcap_open_live():%s \n",errbuf);
         exit(-1);
        }

        if ((packet = pcap_next(descr,&hdr))==NULL)
          {
          printf("ERROR AL CAPTURAR EL PAQUETE \n");
          exit(-1);

        }
          printf("Capturando paquete de tamaño %i \n",hdr.len);
          printf ("Recibido a las %i \n",ctime((const time_t*)&hdr.ts.tv_sec));
          return 0;
       }
