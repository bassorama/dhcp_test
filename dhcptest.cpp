/*H**********************************************************************
* FILENAME :        dhcptest.cpp
*
* DESCRIPTION :
*       Testing script for DHCP server. 
*
*
* NOTES :
*       This script has been tested with Debian 6.0 (amd64) and
*       GCC 4.4.5 (Debian 4.4.5-8), clang 1.1 (Debian 2.7-3).
*       Run the compiled executable with the parameter h for
*       further informations.
*       An example config file(config.txt) is provided with this script.
*
*       
* 
* AUTHOR :    Sebastian Roß       START DATE :    16 Jul 12
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

struct dhcptest
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
} __attribute__((__packed__));

/* Needed for the error handling, saves the errornumber */
int errno;

/* IP array */
int ip_addr[4], *p;
char ip_str[15];

/* file pointer */
FILE *fp;

/* Errorhandling. Writes the reason, as possible, to the terminal */
int die(char* test) {
  printf("dying in honor with : %s\n",test);
  printf("Error: %s\n", strerror(errno));
  exit(1);
}


/* Universal DHCP sender. i = DHCPINFORM, d = DHCPDISCOVER+ -REQUEST, r = DHCPRELEASE  */
int senddhcp(char msg_type, uint8_t mac, char* address, char* sourceaddr) {

  int sockfd,listenfd,connfd;
  const int on=1;
  struct sockaddr_in servaddr,cliaddr,rservaddr;
  if((sockfd=socket(AF_INET,SOCK_DGRAM,0)) < 0)
    die((char*)&"socket");
  if(setsockopt(sockfd,SOL_SOCKET,SO_REUSEADDR,&on,sizeof(on)) < 0)
    die((char*)&"setsockopt");  

  if(setsockopt(sockfd,SOL_SOCKET,SO_BROADCAST,&on,sizeof(on)) < 0)
    die((char*)&"setsockopt");
  bzero(&servaddr,sizeof(servaddr));
  bzero(&cliaddr,sizeof(cliaddr));
  cliaddr.sin_port = htons(68);
  cliaddr.sin_family = AF_INET;
  cliaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  if(bind(sockfd,(struct sockaddr*)&cliaddr,sizeof(cliaddr)) < 0)
    die((char*)&"bind");

  servaddr.sin_port = htons(67);
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = inet_addr(address);

  struct dhcpmessage dhcpmsg;
  bzero(&dhcpmsg,sizeof(dhcpmsg));
  dhcpmsg.op = 1;
  dhcpmsg.htype = 1;
  dhcpmsg.hlen = 6;
  dhcpmsg.hops = 0;
  dhcpmsg.xid = htonl(1000);
  dhcpmsg.secs = htons(0);
  dhcpmsg.flags = htons(0x8000);
  dhcpmsg.chaddr[0] = 0x00;
  dhcpmsg.chaddr[1] = 0x1A;
  dhcpmsg.chaddr[2] = 0x80;
  dhcpmsg.chaddr[3] = 0x80;
  dhcpmsg.chaddr[4] = 0x2C;
  dhcpmsg.chaddr[5] = mac;
  dhcpmsg.magic[0]=99;
  dhcpmsg.magic[1]=130;
  dhcpmsg.magic[2]=83;
  dhcpmsg.magic[3]=99;

  switch(msg_type) {

    //DHCPDISCOVER
    case 'd':{

        dhcpmsg.opt[0]=53;
        dhcpmsg.opt[1]=1;
        dhcpmsg.opt[2]=1;
        dhcpmsg.opt[3]=255;

        if(sendto(sockfd,&dhcpmsg,sizeof(dhcpmsg),0,(struct sockaddr*)&servaddr,sizeof(servaddr)) < 0)
          die((char*)&"sendto");
        printf("(%d) DHCPDISCOVER package sent\n",mac);

        break;
      }

    //DHCPINFORM
    case 'i':{

        //This is the ciaddr that is send as source of DHCPINFORM (Needs to be a char array)
        dhcpmsg.ciaddr = inet_addr(sourceaddr);

        dhcpmsg.opt[0]=53;
        dhcpmsg.opt[1]=1;
        dhcpmsg.opt[2]=8;
        dhcpmsg.opt[3]=255;

        if(sendto(sockfd,&dhcpmsg,sizeof(dhcpmsg),0,(struct sockaddr*)&servaddr,sizeof(servaddr)) < 0)
          die((char*)&"sendto");
        printf("(%d) DHCPINFORM package sent\n",mac);

        break;
      }

    //DHCPRELEASE
    case 'r':{

        //This is the IP address that will be released
        dhcpmsg.ciaddr = inet_addr(ip_str);

        dhcpmsg.opt[0]=53;
        dhcpmsg.opt[1]=1;
        dhcpmsg.opt[2]=7;
        dhcpmsg.opt[3]=255;

        if(sendto(sockfd,&dhcpmsg,sizeof(dhcpmsg),0,(struct sockaddr*)&servaddr,sizeof(servaddr)) < 0)
          die((char*)&"sendto");
        printf("(%d) DHCPRELEASE package sent\n",mac);

        break;
      }

    //default behaviour is to send out an DHCPINFORM package
    default: {

        //This is the ciaddr that is send as source of DHCPINFORM (Needs to be a char array)
        dhcpmsg.ciaddr = inet_addr(sourceaddr);

        dhcpmsg.opt[0]=53;
        dhcpmsg.opt[1]=1;
        dhcpmsg.opt[2]=8;
        dhcpmsg.opt[3]=255;

        if(sendto(sockfd,&dhcpmsg,sizeof(dhcpmsg),0,(struct sockaddr*)&servaddr,sizeof(servaddr)) < 0)
          die((char*)&"sendto");
        printf("(%d) DHCPINFORM package sent\n",mac);

        break;
    }

  }

  /* Writes to the filestream*/
  fputs("---\n", fp);
  char temp_str[30];
  sprintf(temp_str, "(%d) package sent\n",mac);
  fputs(temp_str, fp);

  if (msg_type != 'i') {

    /* here we receive the reply */
    struct timeval timeout;      
    timeout.tv_sec = 3;
    timeout.tv_usec = 0;

    if (setsockopt (sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,
              sizeof(timeout)) < 0)
      die((char*)&"setsockopt failed\n");

    if (setsockopt (sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout,
              sizeof(timeout)) < 0)
      die((char*)&"setsockopt failed\n");

    struct dhcpmessage recvdhcpmsg;
    socklen_t rservlen = sizeof(rservaddr);
    int errorcode = recvfrom(sockfd,&recvdhcpmsg,sizeof(recvdhcpmsg),0,(struct sockaddr*)&rservaddr,&rservlen);
    if (errorcode < 0) {
      printf ("error code (%d)\n",errno);
      if (errno == 11) {
        printf("Timeout, dhcp server is slow\n");
        cout << strerror(errno) << endl;
      } else
        die((char*)&"recvfrom");
    } else {

      struct dhcpmessage replymsg;
      bzero(&replymsg,sizeof(replymsg));
      replymsg = recvdhcpmsg;

      time_t rawtime; 
      time(&rawtime);
      cout << endl;
      cout << "Package received " << ctime(&rawtime) << endl;

      printf("\top <%d>\n",replymsg.op);
      printf("\txid <%u>\n",replymsg.xid);
      printf("\tIP offered <%d.%d.%d.%d>\n",( replymsg.yiaddr >> (0*8) ) & 0xFF,( replymsg.yiaddr >> (1*8) ) & 0xFF,( replymsg.yiaddr >> (2*8) ) & 0xFF,( replymsg.yiaddr >> (3*8) ) & 0xFF);
      printf("\tnext bootstrap server <%d.%d.%d.%d>\n",( replymsg.siaddr >> (0*8) ) & 0xFF,( replymsg.siaddr >> (1*8) ) & 0xFF,( replymsg.siaddr >> (2*8) ) & 0xFF,( replymsg.siaddr >> (3*8) ) & 0xFF);
      printf("\toriginal mac adr <%02X:%02X:%02X:%02X:%02X:%02X>\n",replymsg.chaddr[0],replymsg.chaddr[1],replymsg.chaddr[2],replymsg.chaddr[3],replymsg.chaddr[4],replymsg.chaddr[5]);

      /* Writing to the filestream */
      fputs("Offer received\n", fp);

      sprintf(temp_str, "\top <%d>\n",replymsg.op);
      fputs(temp_str, fp);

      sprintf(temp_str, "\txid <%u>\n",replymsg.xid);
      fputs(temp_str, fp);

      sprintf(temp_str, "\tIP offered <%d.%d.%d.%d>\n",( replymsg.yiaddr >> (0*8) ) & 0xFF,( replymsg.yiaddr >> (1*8) ) & 0xFF,( replymsg.yiaddr >> (2*8) ) & 0xFF,( replymsg.yiaddr >> (3*8) ) & 0xFF);
      fputs(temp_str, fp);

      sprintf(temp_str, "\tnext bootstrap server <%d.%d.%d.%d>\n",( replymsg.siaddr >> (0*8) ) & 0xFF,( replymsg.siaddr >> (1*8) ) & 0xFF,( replymsg.siaddr >> (2*8) ) & 0xFF,( replymsg.siaddr >> (3*8) ) & 0xFF);
      fputs(temp_str, fp);

      sprintf(temp_str, "\toriginal mac adr <%02X:%02X:%02X:%02X:%02X:%02X>\n",replymsg.chaddr[0],replymsg.chaddr[1],replymsg.chaddr[2],replymsg.chaddr[3],replymsg.chaddr[4],replymsg.chaddr[5]);
      fputs(temp_str, fp);

      /* Saving the IP stuff */
      ip_addr[0] = (replymsg.yiaddr >> (0*8) ) & 0xFF;
      ip_addr[1] = (replymsg.yiaddr >> (1*8) ) & 0xFF;
      ip_addr[2] = (replymsg.yiaddr >> (2*8) ) & 0xFF;
      ip_addr[3] = (replymsg.yiaddr >> (3*8) ) & 0xFF;

      if (msg_type == 'd') {

        dhcpmsg.hlen = 6;
        dhcpmsg.xid = replymsg.xid;
        dhcpmsg.chaddr[0] = replymsg.chaddr[0];
        dhcpmsg.chaddr[1] = replymsg.chaddr[1];
        dhcpmsg.chaddr[2] = replymsg.chaddr[2];
        dhcpmsg.chaddr[3] = replymsg.chaddr[3];
        dhcpmsg.chaddr[4] = replymsg.chaddr[4];
        dhcpmsg.chaddr[5] = replymsg.chaddr[5];

        dhcpmsg.opt[0]=53;
        dhcpmsg.opt[1]=1;
        dhcpmsg.opt[2]=3;
        dhcpmsg.opt[3]=50;
        dhcpmsg.opt[4]=4;
        dhcpmsg.opt[5]=( replymsg.yiaddr >> (0*8) ) & 0xFF;
        dhcpmsg.opt[6]=( replymsg.yiaddr >> (1*8) ) & 0xFF;
        dhcpmsg.opt[7]=( replymsg.yiaddr >> (2*8) ) & 0xFF;
        dhcpmsg.opt[8]=( replymsg.yiaddr >> (3*8) ) & 0xFF;
        dhcpmsg.opt[9]=255;
        if(sendto(sockfd,&dhcpmsg,sizeof(dhcpmsg),0,(struct sockaddr*)&servaddr,sizeof(servaddr)) < 0)
          die((char*)&"sendto");
        printf("(ACK) package sent\n",mac);

        sprintf(temp_str, "(ACK) package sent\n",mac);
        fputs(temp_str, fp);
      }

    }

  }

  close(sockfd);

}


/* Just listen for DHCP packages and print to file/terminal */
/* runs in an infinite loop, need to add break option.      */
int to_listen() {

  int sockfd,listenfd,connfd;
  const int on=1;
  struct sockaddr_in servaddr,cliaddr,rservaddr;
  if((sockfd=socket(AF_INET,SOCK_DGRAM,0)) < 0)
    die((char*)&"socket");
  if(setsockopt(sockfd,SOL_SOCKET,SO_REUSEADDR,&on,sizeof(on)) < 0)
    die((char*)&"setsockopt");  

  if(setsockopt(sockfd,SOL_SOCKET,SO_BROADCAST,&on,sizeof(on)) < 0)
    die((char*)&"setsockopt");
  bzero(&servaddr,sizeof(servaddr));
  bzero(&cliaddr,sizeof(cliaddr));
  cliaddr.sin_port = htons(68);
  cliaddr.sin_family = AF_INET;
  cliaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  if(bind(sockfd,(struct sockaddr*)&cliaddr,sizeof(cliaddr)) < 0)
    die((char*)&"bind");

  struct timeval timeout;      
  timeout.tv_sec = 3;
  timeout.tv_usec = 0;

  if (setsockopt (sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,
            sizeof(timeout)) < 0)
    die((char*)&"setsockopt failed\n");

  if (setsockopt (sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout,
            sizeof(timeout)) < 0)
    die((char*)&"setsockopt failed\n");

  struct dhcpmessage recvdhcpmsg;
  socklen_t rservlen = sizeof(rservaddr);
  int errorcode = recvfrom(sockfd,&recvdhcpmsg,sizeof(recvdhcpmsg),0,(struct sockaddr*)&rservaddr,&rservlen);
  if (errorcode < 0) {
    if (errno == 11)
      printf("");
    else
      die((char*)&"recvfrom");
  } else {

    struct dhcpmessage replymsg;
    bzero(&replymsg,sizeof(replymsg));
    replymsg = recvdhcpmsg;

    time_t rawtime; 
    time(&rawtime);
    cout << endl;
    cout << "Received Package " << ctime(&rawtime);
    cout << "\top <" << replymsg.op << ">" << endl;
    cout << "\txid <" << replymsg.xid << ">" << endl;
    cout << "\tIP offered <" << (replymsg.yiaddr >> (0*8) & 0xFF) << "." << (replymsg.yiaddr >> (1*8) & 0xFF) << "." << (replymsg.yiaddr >> (2*8) & 0xFF) << "." << (replymsg.yiaddr >> (3*8) & 0xFF) << ">" << endl;
    cout << "\tnext bootstrap server <" << (replymsg.siaddr >> (0*8) & 0xFF) << "." << (replymsg.siaddr >> (0*8) & 0xFF) << "." << (replymsg.siaddr >> (0*8) & 0xFF) << "." << (replymsg.siaddr >> (0*8) & 0xFF) << ">" << endl; 
    // cout << "\toriginal mac adr <" << replymsg.chaddr[0] << ":" << replymsg.chaddr[0] << ":" << replymsg.chaddr[1] << ":" << replymsg.chaddr[2] << ":" << replymsg.chaddr[3] << ":" << replymsg.chaddr[4] << replymsg.chaddr[5] << ">" << endl;
    printf("\toriginal mac adr <%02X:%02X:%02X:%02X:%02X:%02X>\n",replymsg.chaddr[0],replymsg.chaddr[1],replymsg.chaddr[2],replymsg.chaddr[3],replymsg.chaddr[4],replymsg.chaddr[5]);

  }

}


/* Main routine, implements a simple terminal menu.Take care that the order of options in the config file is the same order as the */
/* cin of the interactive menu, else that might upset the script.                                                                  */
int main(int argc, char *argv[]) {
  uint8_t i=0;

  char* sourceaddr = new char[15];
  // sourceaddr = new char[15];
  char* address = new char[15];
  char* release_bool = new char[1];
  int interval;
  char* rand_bool = new char[1];

  char ch;
  char filename[150];
  char configfile[150];
  char msg_type;
  string inputparam;

  if(argc == 1) {
    cout << "No valid parameters given. Try " << argv[0] << " -h for help" << endl;
    exit(1);
  }

  sprintf(filename, "%s", argv[0]);

  inputparam = argv[1];

  switch(inputparam[1]) {
    case 'l': {
      cout << "Listening.." << endl;
      for(;;) {
        to_listen();
      }
      break;
    }

    case 's': {

      if(argc == 3) {
        /* Support for a very simple config file, it has to feature the sourceaddress, destinationaddress,whether the IPs should be    */
        /* released number of packages, and whether the MAC Addresses should be random. ((exactly!)same order as the interactive menu) */

        string templine;
        string tempstr;
        int i;

        ifstream infiletest(argv[2]);

        getline(infiletest, templine);
        i = templine.find("[");
        tempstr.assign(templine, i+1, templine.size());
        tempstr.erase(tempstr.find("]"));
        strcpy( sourceaddr, tempstr.c_str());

        getline(infiletest, templine);
        i = templine.find("[");
        tempstr.assign(templine, i+1, templine.size());
        tempstr.erase(tempstr.find("]"));
        strcpy( address, tempstr.c_str());

        getline(infiletest, templine);
        i = templine.find("[");
        tempstr.assign(templine, i+1, templine.size());
        tempstr.erase(tempstr.find("]"));
        strcpy( release_bool, tempstr.c_str());

        getline(infiletest, templine);
        i = templine.find("[");
        tempstr.assign(templine, i+1, templine.size());
        tempstr.erase(tempstr.find("]"));
        interval = atoi(tempstr.c_str());

        getline(infiletest, templine);
        i = templine.find("[");
        tempstr.assign(templine, i+1, templine.size());
        tempstr.erase(tempstr.find("]"));
        strcpy( rand_bool, tempstr.c_str());

      } else {

        /* Interactive input for the test parameters, asking for broadcast adress, number of packages and whether the IPs should be released */

        cout << "Please input your IP adress:" << endl;
        cin >> sourceaddr;

        cout << "Please input the broadcast address of your network:" << endl;
        cin >> address;

        cout << "Do you want to release assigned IPs? (y or n)" << endl;
        cin >> release_bool;

        cout << "Please input the number of packages to be send:" << endl;
        cin >> interval;

        cout << "Generate random mac addresses? (y or n)" << endl;
        cin >> rand_bool;

      }

      /* Open a file pointer */
      if ((fp = fopen("output.txt", "w+"))==NULL) {
        cout << "Cannot open the file." << endl;
        exit(1);
      }

      /* This sends a specified number of DHCPINFORM, DHCPDISCOVER and DHCPRELEASE packages, number is specified in interval */
      for(i=40;i<40+interval;i++) {
        int j;
        if (rand_bool[0] == 'y')
          j = rand();
        else
          j = i;
        msg_type = 'i';
        senddhcp(msg_type, j, address, sourceaddr);
        msg_type = 'd';
        senddhcp(msg_type, j, address, sourceaddr);
        //This saves the IP given by the latest DHCPOFFER in a global char array so that dhcp_release can access it
        sprintf(ip_str, "%u.%u.%u.%u", ip_addr[0], ip_addr[1], ip_addr[2], ip_addr[3]);
        if (release_bool[0] == 'y')
          msg_type = 'r';
          senddhcp(msg_type, j, address, sourceaddr);
        cout << "---" << endl;
      }

      /* Closing the file pointer */
      fclose(fp);
      break;

    }

    case 'h': {
      cout << filename << " -l: Listen for DHCP packages send to this machine." << endl;
      cout << filename << " -s: Send DHCP packages. Additional Parameter specifices a config file." << endl;
      break;
    }

    // this parameter is just meant for testing stuff
    case 't': {

      struct dhcptest testmsg;
      cout << sizeof(testmsg) << endl;
      char* testptr = new char[sizeof(testmsg)+10];

      testmsg.op = 1;
      testmsg.htype = 1;
      testmsg.hlen = 6;
      testmsg.hops = 0;
      testmsg.xid = htonl(1000);
      testmsg.secs = htons(0);
      testmsg.flags = htons(0x8000);
      testmsg.chaddr[0] = 0x00;
      testmsg.chaddr[1] = 0x1A;
      testmsg.chaddr[2] = 0x80;
      testmsg.chaddr[3] = 0x80;
      testmsg.chaddr[4] = 0x2C;
      testmsg.chaddr[5] = 0x05;
      testmsg.magic[0]=99;
      testmsg.magic[1]=130;
      testmsg.magic[2]=83;
      testmsg.magic[3]=99;

      testptr[(sizeof(testmsg)+0)]=5;
      testptr[(sizeof(testmsg)+1)]=3;
      testptr[(sizeof(testmsg)+2)]=1;
      testptr[(sizeof(testmsg)+3)]=8;
      testptr[(sizeof(testmsg)+4)]=2;
      testptr[(sizeof(testmsg)+5)]=5;
      testptr[(sizeof(testmsg)+6)]=5;

      cout << " " << endl;

      for(i=sizeof(testmsg); i<sizeof(testmsg)+10; i++) {
        cout << dec << (int)testptr[i] << endl;
      }

      delete[] testptr;

      break;
    }

    default:
      cout << "No valid parameters give. Try -h for help." << endl;
      break;

  }

  return 0;
}