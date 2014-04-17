/*H**********************************************************************
* FILENAME :        listener.cpp
*
* DESCRIPTION :
*       Can listen for DHCP Messages and writes them to stdout.
*
*
* NOTES :
*       This script has been tested with Debian 7.0 (amd64) and
*       gcc (Debian 4.7.2-5) 4.7.2.
*       Run the compiled executable with the parameter h for
*       further informations.
*
*       
* 
* AUTHOR :    Sebastian Roß       START DATE :    10 Apr 14
*
* CHANGES :
*
*
*
*
*H*/

#include<stdio.h>
#include<ctype.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<signal.h>
#include<sys/wait.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<errno.h>
#include<sys/file.h>
#include<sys/msg.h>
#include<sys/ipc.h>
#include<time.h>
#include<errno.h>
#include<iostream>
#include<fstream>
#include<ctime>
#include<string>


using namespace std;

/* the strucuts dhcpmessage and dhcpreplymessage are basicly the same, the reply message just got more options */
struct dhcpmessage
{
  uint8_t op;
  uint8_t htype;
  uint8_t hlen;
  uint8_t hops;
  uint32_t xid;
  uint16_t secs;
  uint16_t flags;
  uint32_t ciaddr;
  uint32_t yiaddr;
  uint32_t siaddr;
  uint32_t giaddr;
  uint8_t chaddr[16];
  char sname[64];
  char file[128];
  char magic[4];
  char opt[10];
} __attribute__((__packed__));


/* Needed for the error handling, saves the errornumber */
int errno;


/* Errorhandling. Writes the reason, as possible, to the terminal */
int error_handling(char* msg) {
  printf("Exception at: %s\n",msg);
  printf("Error: %s\n", strerror(errno));
  exit(1);
}

/* Just listen for DHCP packages and print to file/terminal */
/* runs in an infinite loop, need to add break option.      */
int to_listen() {

  int sockfd,listenfd,connfd;
  const int on=1;
  struct sockaddr_in servaddr,cliaddr,rservaddr;
  if((sockfd=socket(AF_INET,SOCK_DGRAM,0)) < 0)
    error_handling((char*)&"socket");
  if(setsockopt(sockfd,SOL_SOCKET,SO_REUSEADDR,&on,sizeof(on)) < 0)
    error_handling((char*)&"setsockopt");  

  if(setsockopt(sockfd,SOL_SOCKET,SO_BROADCAST,&on,sizeof(on)) < 0)
    error_handling((char*)&"setsockopt");

  bzero(&servaddr,sizeof(servaddr));
  bzero(&cliaddr,sizeof(cliaddr));
  cliaddr.sin_port = htons(68);
  cliaddr.sin_family = AF_INET;
  cliaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  if(bind(sockfd,(struct sockaddr*)&cliaddr,sizeof(cliaddr)) < 0)
    error_handling((char*)&"bind");

  struct timeval timeout;      
  timeout.tv_sec = 3;
  timeout.tv_usec = 0;

  if (setsockopt (sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,
            sizeof(timeout)) < 0)
    error_handling((char*)&"setsockopt failed\n");

  if (setsockopt (sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout,
            sizeof(timeout)) < 0)
    error_handling((char*)&"setsockopt failed\n");

  struct dhcpmessage recvdhcpmsg;
  socklen_t rservlen = sizeof(rservaddr);

  int errorcode = recvfrom(sockfd,&recvdhcpmsg,sizeof(recvdhcpmsg),0,(struct sockaddr*)&rservaddr,&rservlen);
  
  if (errorcode < 0) {
    if (errno == 11)
      printf("");
    else
      error_handling((char*)&"recvfrom");
  } else {

    time_t rawtime; 
    time(&rawtime);
    cout << endl;
    cout << "Received Package " << ctime(&rawtime);
    cout << "\top <" << dec << recvdhcpmsg.op << ">" << endl;
    cout << "\txid <" << dec << recvdhcpmsg.xid << ">" << endl;
    cout << "\tIP offered <" << dec << (recvdhcpmsg.yiaddr >> (0*8) & 0xFF) << "." << (recvdhcpmsg.yiaddr >> (1*8) & 0xFF) << "." << (recvdhcpmsg.yiaddr >> (2*8) & 0xFF) << "." << (recvdhcpmsg.yiaddr >> (3*8) & 0xFF) << ">" << endl;
    cout << "\tnext bootstrap server <" << dec << (recvdhcpmsg.siaddr >> (0*8) & 0xFF) << "." << (recvdhcpmsg.siaddr >> (0*8) & 0xFF) << "." << (recvdhcpmsg.siaddr >> (0*8) & 0xFF) << "." << (recvdhcpmsg.siaddr >> (0*8) & 0xFF) << ">" << endl; 
    cout << "\toriginal mac adr <" << hex << static_cast<int>(recvdhcpmsg.chaddr[0]) << ":" << static_cast<int>(recvdhcpmsg.chaddr[1]) << ":" << static_cast<int>(recvdhcpmsg.chaddr[2]) << ":" << static_cast<int>(recvdhcpmsg.chaddr[3]) << ":" << static_cast<int>(recvdhcpmsg.chaddr[4]) << ":" << static_cast<int>(recvdhcpmsg.chaddr[5]) << ">" << endl;

  }

}



int main(int argc, char *argv[]) {

  cout << "Listening.." << endl;
  for(;;) {
    to_listen();
  }

  return 0;
}