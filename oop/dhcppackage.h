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

class dchppackage {

  private:
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

    // struct* dhcpmessage this_msg;


  public:
    dchppackage(void);
    ˜dhcppackage(void);
    dhcpmessage* getPackage();
    void setPackageType(char[]);
    


}