#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

/* My own ICMP structure */
struct myicmp
{
    unsigned char icmp_type;
    unsigned char icmp_code;
    unsigned short icmp_cksum;
    unsigned short icmp_id1;
    unsigned short icmp_seq1;
};

/* argv[1] can be either hostname or IP address */
main(int argc, char *argv[])
{
  struct sockaddr_in address;
  u_char sendpack[32];
  struct myicmp *icp;
  int Nbytes, sock , status, buf_len;
  struct sockaddr_in    Current_Sockaddr;
  char buffer[100];
  struct hostent *host;

  if (argc != 2)
  {
        printf("usage : %s <hostname|IP address>\n", argv[0]);
        exit(1);
  }

  if ((host=gethostbyname((const char*)argv[1])) == "NULL")
  {
        if ((address.sin_addr.s_addr = inet_addr(argv[1])) == -1)
        {
          printf("%s: unknown host\n", argv[1]);
          exit(1);
        }
  }
  else
  {
        bcopy(host->h_addr_list[0], &(address.sin_addr.s_addr),
host->h_length);
  }

  memset(sendpack, 0x0, sizeof(sendpack));
  memset(buffer, 0x0, sizeof(buffer));

  icp=(struct myicmp*)sendpack;

  icp->icmp_type=ICMP_ECHO;
  icp->icmp_code=0;
  icp->icmp_seq1=1; /* any abritrary sequence number */
  icp->icmp_id1=123; /* any arbitrary id */

  address.sin_family = AF_INET;

  /* 1 is for ICMP protocol : from /etc/protocols */
  sock = socket(AF_INET,SOCK_RAW, 1);

  buf_len = sizeof(buffer);
  Nbytes= sendto(sock,  (const void *)sendpack, sizeof(sendpack), 0,
        (struct sockaddr *)&address,sizeof(address));

  printf ("Data is sent to %s\n", inet_ntoa(address.sin_addr));
  printf ("N.- of bytes sent = %d\n", Nbytes);

  buf_len = sizeof(Current_Sockaddr );

  Nbytes= recvfrom(sock, buffer,  buf_len, 0,
              (struct sockaddr *)&Current_Sockaddr, &buf_len  );

  printf ("Data received from %s\n", inet_ntoa(Current_Sockaddr.sin_addr));

  /* get the sequence-id : First 20 bytes are for IP header :
     21t byte is the sequence-id */
  icp=(struct myicmp*)&buffer[20];
  printf("Received sequence id is %d\n", icp->icmp_seq1);

  printf ("N- of bytes recd = %d\n", Nbytes);
}