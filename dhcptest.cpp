/*H**********************************************************************
* FILENAME :        dhcptest.cpp
*
* DESCRIPTION :
*       Testing script for DHCP server. 
*
*
* NOTES :
*       This script has been tested with Debian 7.0 (amd64) and
*       gcc (Debian 4.7.2-5) 4.7.2.
*       Run the compiled executable with the parameter h for
*       further informations.
*       An example config file(config.txt) is provided with this script.
*
*       
* 
* AUTHOR :    Sebastian Roß       START DATE :    14 Apr 14
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
struct dhcpmessage {
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

struct host {
  int ip_addr[4];
  uint8_t chaddr[16];
};

/* Needed for the error handling, saves the errornumber */
int errno;

/* IP array */
int ip_addr[4], *p;
char ip_str[15];

/* file pointer */
FILE *fp;

/* Errorhandling. Writes the reason, as possible, to stdout */
int exception_handler(char* test) {
  cout << "Exception at: " << test << endl;
  cout << "Error: " << strerror(errno);
  exit(1);
}


/* Universal DHCP sender. i = DHCPINFORM, d = DHCPDISCOVER+ -REQUEST, r = DHCPRELEASE  */
void senddhcp(char msg_type, uint8_t mac, char* address, char* sourceaddr) {

  int sockfd,listenfd,connfd;
  const int on=1;
  struct sockaddr_in servaddr,cliaddr,rservaddr;
  if((sockfd=socket(AF_INET,SOCK_DGRAM,0)) < 0)
    exception_handler((char*)&"socket");
  if(setsockopt(sockfd,SOL_SOCKET,SO_REUSEADDR,&on,sizeof(on)) < 0)
    exception_handler((char*)&"setsockopt");  

  if(setsockopt(sockfd,SOL_SOCKET,SO_BROADCAST,&on,sizeof(on)) < 0)
    exception_handler((char*)&"setsockopt");
  bzero(&servaddr,sizeof(servaddr));
  bzero(&cliaddr,sizeof(cliaddr));
  cliaddr.sin_port = htons(68);
  cliaddr.sin_family = AF_INET;
  cliaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  if(bind(sockfd,(struct sockaddr*)&cliaddr,sizeof(cliaddr)) < 0)
    exception_handler((char*)&"bind");

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
          exception_handler((char*)&"sendto");
        cout << "(" << int(mac) << ") DHCPDISCOVER package sent" << endl;

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
          exception_handler((char*)&"sendto");
        cout << "(" << int(mac) << ") DHCPINFORM package sent" << endl;

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
          exception_handler((char*)&"sendto");
        cout << "(" << int(mac) << ") DHCPRELEASE package sent" << endl;

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
          exception_handler((char*)&"sendto");
        cout << "(" << mac << ") DHCPINFORM package sent" << endl;

        break;
    }

  }

  char temp_str[30];
  sprintf(temp_str, "(%d) package sent\n",mac);

  if (msg_type != 'i') {

    /* here we receive the reply */
    struct timeval timeout;      
    timeout.tv_sec = 3;
    timeout.tv_usec = 0;

    if (setsockopt (sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,
              sizeof(timeout)) < 0)
      exception_handler((char*)&"setsockopt failed\n");

    if (setsockopt (sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout,
              sizeof(timeout)) < 0)
      exception_handler((char*)&"setsockopt failed\n");

    struct dhcpmessage recvdhcpmsg;
    socklen_t rservlen = sizeof(rservaddr);
    int errorcode = recvfrom(sockfd,&recvdhcpmsg,sizeof(recvdhcpmsg),0,(struct sockaddr*)&rservaddr,&rservlen);
    if (errorcode < 0) {
      printf ("error code (%d)\n",errno);
      if (errno == 11) {
        cout << "Timeout, dhcp server is slow" << endl;
        cout << strerror(errno) << endl;
      } else
        exception_handler((char*)&"recvfrom");
    } else {

      struct dhcpmessage replymsg;
      bzero(&replymsg,sizeof(replymsg));
      replymsg = recvdhcpmsg;

      time_t rawtime; 
      time(&rawtime);
      cout << endl;
      cout << "Package received " << ctime(&rawtime) << endl;
      
      cout << "\top <" << dec << replymsg.op << ">" << endl;
      cout << "\txid <" << dec << replymsg.xid << ">" << endl;
      cout << "\tIP offered <" << dec << (replymsg.yiaddr >> (0*8) & 0xFF) << "." << (replymsg.yiaddr >> (1*8) & 0xFF) << "." << (replymsg.yiaddr >> (2*8) & 0xFF) << "." << (replymsg.yiaddr >> (3*8) & 0xFF) << ">" << endl;
      cout << "\tnext bootstrap server <" << dec << (replymsg.siaddr >> (0*8) & 0xFF) << "." << (replymsg.siaddr >> (0*8) & 0xFF) << "." << (replymsg.siaddr >> (0*8) & 0xFF) << "." << (replymsg.siaddr >> (0*8) & 0xFF) << ">" << endl; 
      cout << "\toriginal mac adr <" << hex << static_cast<int>(replymsg.chaddr[0]) << ":" << static_cast<int>(replymsg.chaddr[1]) << ":" << static_cast<int>(replymsg.chaddr[2]) << ":" << static_cast<int>(replymsg.chaddr[3]) << ":" << static_cast<int>(replymsg.chaddr[4]) << ":" << static_cast<int>(replymsg.chaddr[5]) << ">" << endl;
      

      /*
      printf("\top <%d>\n",replymsg.op);
      printf("\txid <%u>\n",replymsg.xid);
      printf("\tIP offered <%d.%d.%d.%d>\n",( replymsg.yiaddr >> (0*8) ) & 0xFF,( replymsg.yiaddr >> (1*8) ) & 0xFF,( replymsg.yiaddr >> (2*8) ) & 0xFF,( replymsg.yiaddr >> (3*8) ) & 0xFF);
      printf("\tnext bootstrap server <%d.%d.%d.%d>\n",( replymsg.siaddr >> (0*8) ) & 0xFF,( replymsg.siaddr >> (1*8) ) & 0xFF,( replymsg.siaddr >> (2*8) ) & 0xFF,( replymsg.siaddr >> (3*8) ) & 0xFF);
      printf("\toriginal mac adr <%02X:%02X:%02X:%02X:%02X:%02X>\n",replymsg.chaddr[0],replymsg.chaddr[1],replymsg.chaddr[2],replymsg.chaddr[3],replymsg.chaddr[4],replymsg.chaddr[5]);
      */

      cout << "\top <" << dec << recvdhcpmsg.op << ">" << endl;
      cout << "\txid <" << dec << recvdhcpmsg.xid << ">" << endl;
      cout << "\tIP offered <" << dec << (recvdhcpmsg.yiaddr >> (0*8) & 0xFF) << "." << (recvdhcpmsg.yiaddr >> (1*8) & 0xFF) << "." << (recvdhcpmsg.yiaddr >> (2*8) & 0xFF) << "." << (recvdhcpmsg.yiaddr >> (3*8) & 0xFF) << ">" << endl;
      cout << "\tnext bootstrap server <" << dec << (recvdhcpmsg.siaddr >> (0*8) & 0xFF) << "." << (recvdhcpmsg.siaddr >> (0*8) & 0xFF) << "." << (recvdhcpmsg.siaddr >> (0*8) & 0xFF) << "." << (recvdhcpmsg.siaddr >> (0*8) & 0xFF) << ">" << endl; 
      cout << "\toriginal mac adr <" << hex << static_cast<int>(recvdhcpmsg.chaddr[0]) << ":" << static_cast<int>(recvdhcpmsg.chaddr[1]) << ":" << static_cast<int>(recvdhcpmsg.chaddr[2]) << ":" << static_cast<int>(recvdhcpmsg.chaddr[3]) << ":" << static_cast<int>(recvdhcpmsg.chaddr[4]) << ":" << static_cast<int>(recvdhcpmsg.chaddr[5]) << ">" << endl;

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
          exception_handler((char*)&"sendto");
        cout << "(ACK) package sent (" << int(mac) << ")" << endl;

        //sprintf(temp_str, "(ACK) package sent\n",mac);
      }

    }

  }

  close(sockfd);

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
      cout << filename << " -s: Send DHCP packages. Additional Parameter specifices a config file." << endl;
      break;
    }

    default:
      cout << "No valid parameters given. Try -h for help." << endl;
      break;

  }

  return 0;
}