#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/int.h>
#include <arpa/inet.h>
#include <time.h>
#include <netinet/if_ethet.h>
#include <string.h>
#define SIZE 100

struct arpstruct{
	u_char arp_mac[6];
	u_char arp_ip[4];

};

pcap_t *descriptor;

unsigned int x_hours=0;
unsigned int x_minutes=0;
unsigned int x_seconds=0;
unsigned int x_milliseconds=0;
unsigned int totaltime=0;
unsigned int countdown=0;
unsigned int tiempoperdido=0;
clock_t x_starttime;
clock_t x_counttime;
///definimos las funcionaes que vamos a usar
void arpspoofin();

void arpspoofin()
{

	char *netid;
	char *maskid;
	char *device;
	char errbuf[PCAP_ERRBUF_SIZE];
	const u_char *packete;
	struct pcap_pkthdr hdr;//cabezera o header
	struct ether_heather *eptr;
	struct bpf_program fp;

	bpf_u_int32 maskp;
	bpf_u_int32 netp;

	char filter_exp[]="udp dst port 8080";
	int filtro;
	int compiler;

	char nombreArchivo[40];
	char *extencion=".pcap";
	char  archivo[200] = "/home/kevin/Proyecto de Redes de Computadoras/Proyecto-de-Computadoras/"
    pcap_if_t *dispositivosdisponibles;
    pcap_if_t *dispositivo;
    pcap_t *handle;
    char errbufDispositivos[50];
    char devs[50];
    int count=0;
    int number;

    struct arpstruct datos[50];
    struct arp_struct frame;

    int i,j=0,y;
    char opciones[3];
     do
     {
     	printf("*************************************ARP SPOOFIN*******************\n");
     	printf("-i DEV,especifica la interface de red con la cual hacer sniff.\n ");
     	printf("-r FILE, lee el trafico de red de un archivo \n");
     	printf("Digite su opcion \t");
     	scanf("%s",opciones);
     	    if(strcmp(opciones,"-i")==0)
     	    {
     	    	//Esta condicion conjunta con la funcion es encontrar todos los dispositivos que se encuentran habilitados 
     	    	   if(pcap_findalldevs(&dispositivosdisponibles,errbuf))
     	    	   {
     	    	   	 printf("NO SE ENCONTRO NINGUN DISPOSITIVO %s",errbuf);
     	    	   	 exit(1);
     	    	   }
                
     	    	   for(dispositivos=dispositivosdisponibles;dispositivos !=NULL ;dispositivos=dispositivos->next)
     	    	   {
     	    	   	printf("%d->%s --->%s \n",count,dispositivos->name,dispositivos->description);
     	    	   	 if(dispositivos->name !=NULL)
     	    	   	 {
     	    	   	 	strcpy(devs[count],device->name);
     	    	   	 }
     	    	   	 count++;

     	    	   }

     	    	   printf("Numero de dispositivo para hacer Sniffing \n");
     	    	   scanf("%d",&number);
     	    	   printf("Tiempo de lapso maximo para hacer deteccion");
     	    	   scanf("%d",&countdown);
     	    	   dev=devs[number];
                 //***********
                   printf("\t Dispositivo :%s \t con un tiempo maximo %d seg /n",device,countdown);

                  //Direccion de red y mascara obtenemos
     	    	   pcap_lookupnet(dev,%netp,&maskp,errbuf);
     	    	   
                   descriptor=pcap_open_live(dev,SIZE,1,15,errbuf);
                   if(descriptor == NULL)
                   {
                   	 printf("pcap_open_live(): %s \n",errbuf );
                   	 exit(1);
                   }

                   compiler=pcap_compile(desc,&fp,"arp",0,netp);
                    
                    if(compiler<0)
                    {
                    	printf("ERROR AL COMPILAR FILTRO \n");
                    	exit(1);
                    }
 
                    filtro=pcap_setfilter(descriptor,&fp);
                    
                    if(filtro < 0)
                    {
                        fprintf(stderr, "error aplicando filtro\n");
                    }
                    struct pcap_pkthdr *header;
                    const u_char *data;
                    u_int contadorpackete=0;
                    int valorretorno;
                    int repetir=0;
                     while(valorretorno=pcap_next_ex(descr,&header,&data) >= 0)
                     {
                        contadorpackete++;
                     	if ( data != NULL)
                     	{
                     		const struct pcap_pkthdr* pkthdr=header;
                     		count=contadorpackete;
                     		packete=data;
                     		u_int i;

                              ///*****************************
                            if(repetir != header->ts.tv_usec)
                     	    {

                              

                                        printf("N.-Packet %i \n",contadorpackete);
                                        printf("tamaño Paquete : %i \n",header->len); 

                                 
                                        //validaciones
                                        if(header->len != header->caplen)
                                        {
                                        printf("SE CAPTURO TAMAÑOS DIFERENTE PARA ESE PACKETE : %i byte \n ",header->len);
                                        printf("Tiempo transcurrido  %li %li segundos",header->ts.tv_sec,header->ts.tv_usec);
                                    
                                        }

                                            int igualmac=0;
                                            int igualip=0;
                                            int spoofarp=0;
                                            int v=0;
                                            char resp=(char )2;




                                  
                                   for(i=0;(i <header->caplen);i++)
                                   {
                                     if(i==21 && (data[i]==resp))
                                     {
                                        if(j==0)
                                        {
                                       
                                        for(n=0;n<6;n++)
                                        {
                                         datos[j].arp_mac[n]=data[22+n];
                                        }

                                        for (n=0 ; n<4 ;n++)
                                        {
                                          datos[j].arp_ip[n]=data[28+n];  
                                        }
                                         

                                        }

                                        else
                                        {
                                         int flagip=0;
                                         int flagmac=0;
                                         int px,py;
                                         for(px=0;px < j;px++)
                                         {
                                            for(py=0;py<4;py++)
                                            {
                                                if(data[28+py]==datos[px].arp_ip[py])
                                                {
                                                    igualip++;
                                                }
                                            }
                                         } 

                                         if (igualip==4)
                                         {
                                           flagip=1;
                                           flagmac=1;
                                           break;
                                         }       

                                          //*************
                                         igualip=0;



                                        }

                                        if (flagmac)
                                        {
                                            int mx,my;
                                             for(my=0;my < 6;my++)
                                             {
                                                if(data[22+my] == datos[px].arp_mac[my])
                                                 {
                                                    igualmac++;
                                                 }   
                                             }

                                             if(igualmac != 6)
                                             {
                                                spoofarp=1;
                                                v=mx;

                                             }
                                             igualmac=0;
                                             j--;
                                        }

                                        else
                                        {
                                            for(n=0;n<6;n++)
                                            {
                                                datos[j].arp_mac[n]=data[22+n];
                                            }

                                            for(n=0;n<4;n++)
                                            {
                                                datos[j].arp_ip[n]=data[28+n];
                                            }

                                        }

                                     }

                                     j++;
                                   } 

                                       if(i%16 == 0)
                                        {
                                        printf("\n");
                                        printf("%.2x",data[i]);

                                        }
                                        if(spoofarp==1)
                                        {
                                        printf("\n\tDETECT: Who-has %i.%i.%i.%i, R1: %x:%x:%x:%x:%x:%x,  R2:  %x:%x:%x:%x:%x:%x, TS: %li . %li \n"
                                        ,data[28],data[29],data[30],data[31]
                                        ,datos[v].arp_mac[0], datos[v].arp_mac[1], datos.arp_mac[2], datos.arp_mac[3],datos.arp_mac[4], datos[v].arp_mac[5]
                                        ,data[22],data[23],data[24],data[25],data[26], data[27]
                                        ,header->ts.tv_sec, header->ts.tv_usec);
                                        }

                                        printf("\n\n");
                                        repetir=header->ts.tv_usec; 
                            }







                              //****

                           
                     		  	      
                        }
                   }
     	    }

        else if(strcmp(opciones,"-r")==0)
        {
            printf("ingrese el nombre del archivo \n ");
            scanf("%s",nombreArchivo);

            strcat(FILE,nombreArchivo);
            strcat(FILE,extension);

            pcap_t *pcap=pcap_open_offline(nombreArchivo,errbuf);
            struct pcap_pkthdr *header;
            const u_char *data;


            u_int packetcount=0;
            int  returnvalue;
            int arpi=0;
            int d=0;
            char resp= (char )2;

             while(returnvalue =pcap_next_ex(pcap,&header,$data)>=0)
             {
                  packetcount++;
                  const struct pcap_pkthdr* pkthdr=header;
                  int count=packetcount;
                  const u_char* packet = data;
                  u_int i;

                  printf("Packete N.- %d",packetcount);
                  printf("Longitud del packete %d",header->len);

                  if(header->len != header->caplen)
                  

                    {
                    printf("Capturo packetes de diferentes tamaño");
                    printf("time %li:%li seg \n",header->ts.tv_sec,header->ts.tv_usec);
                     }
                    int coincidemac=0;
                    int coincideip=0;
                    int spoofarp=0;
                    int v=0;

                      for (i=0; (i <header->caplen) ; i++){
                              if(i==21 && (data[i] == resp))
                              {
                                    if (j==0)
                                    {
                                          /* code */
                                          for(n=0; n<6;n++)
                                          {
                                                datos[j].arp_mac[n]=data[22+n] ;
                                          }
                                          for(n=0; n<4;n++)
                                          {
                                                datos[j].arp_ip[n]=data[28+n] ;
                                          }
                                    }
                                    else
                                    {
                                          int banderaIp=0;
                                          int banderaMac=0;
                                          int ipX, ipY;

                                          for (ipX = 0; ipX < j; ipX++)
                                          {
                                                for (ipY = 0; ipY < 4; ipY++)
                                                {
                                                      if (data[28+ipY] == datos[ipX].arp_ip[ipY])
                                                      {
                                                            coincideip++;
                                                      }
                                                }
                                                if (coincideip == 4)
                                                {
                                                      banderaIp =1;
                                                      break;
                                                }
                                            
                                                coincideip=0;
                                          }
                                          if (banderaIp != 0){
                                                banderaMac = 1;
                                          }

                                          if (banderaMac == 1)
                                          {
                                                int macX, macY;
                                                      for (macY = 0; macY  < 6; macY++)
                                                      {
                                                            if (data[22+macY] == datos[ipX].arp_mac[macY])
                                                            {
                                                                  coincideip++;
                                                            }
                                                      }
                                                      if (coincidemac != 6){
                                                            spoofarp = 1;
                                                            v = macX;
                                                      }
                                                      coincidemac = 0;
                                                j--;
                                          }
                                          else{
                                                for(n=0; n<6;n++){
                                                      datos[j].arp_mac[n]=data[22+n] ;
                                                }
                                                for(n=0; n<4;n++){
                                                      datos[j].arp_ip[n]=data[28+n] ;
                                                }     
                                          }
                                    }
                                    j++;
                              }
                        }
                            if ( (i % 16) == 0) {
                           printf("\n"); // Start printing on the next after every 16 octets
                            printf("%.2x ", data[i]); // Print each octet as hex (x), make sure there is always two characters (.2).   
                        }
                        if (spoofarp == 1){
                              printf("\n\tDETECT: Who-has %i.%i.%i.%i, R1: %x:%x:%x:%x:%x:%x,  R2:  %x:%x:%x:%x:%x:%x, TS: %li . %li \n"
                                    ,data[28],data[29],data[30],data[31]
                                    ,datos[v].arp_mac[0], datos[v].arp_mac[1], datos[v].arp_mac[2], datos[v].arp_mac[3], datos[v].arp_mac[4], datos[v].arp_mac[5]
                                    ,data[22],data[23],data[24],data[25],data[26], data[27]
                                    ,header->ts.tv_sec, header->ts.tv_usec);
                        }
                        printf("\n\n");          // Add two lines between packets    



                  

                //*****************************************************************************************
                  

             }

        
        }
        
     }while((strcmp(opciones,"-i") != 0) && (strcmp(opciones,"-r") != 0);

}




