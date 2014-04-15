#include "dhcppackage.h"

dhcppackage::dhcppackage() {

  struct dhcpmessage this_msg;
  bzero(&this_msg,sizeof(this_msg));

}

dhcppackage::˜dhcppackage() {

}

dhcppackage::setPackageType(char[] type) {

  if (type == "DISCOVER") {
    this_msg.opt[0]=53;
    this_msg.opt[1]=1;
    this_msg.opt[2]=1;
    this_msg.opt[3]=255;
  }


}