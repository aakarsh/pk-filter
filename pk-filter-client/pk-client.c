#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/types.h>

#include <netlink/cache.h>
#include <netlink/route/link.h>

#include <linux/filter.h>

#include "pk-netlink.h"

#define NETLINK_PK_FILTER 31

struct sock_filter tcp_filter [] = {
{ 0x28, 0, 0, 0x0000000c },
{ 0x15, 27, 0, 0x000086dd },
{ 0x15, 0, 26, 0x00000800 },
{ 0x30, 0, 0, 0x00000017 },
{ 0x15, 0, 24, 0x00000006 },
{ 0x28, 0, 0, 0x00000014 },
{ 0x45, 22, 0, 0x00001fff },
{ 0xb1, 0, 0, 0x0000000e },
{ 0x48, 0, 0, 0x0000000e },
{ 0x15, 2, 0, 0x00000050 },
{ 0x48, 0, 0, 0x00000010 },
{ 0x15, 0, 17, 0x00000050 },
{ 0x28, 0, 0, 0x00000010 },
{ 0x2, 0, 0, 0x00000001 },
{ 0x30, 0, 0, 0x0000000e },
{ 0x54, 0, 0, 0x0000000f },
{ 0x64, 0, 0, 0x00000002 },
{ 0x7, 0, 0, 0x00000005 },
{ 0x60, 0, 0, 0x00000001 },
{ 0x1c, 0, 0, 0x00000000 },
{ 0x2, 0, 0, 0x00000005 },
{ 0xb1, 0, 0, 0x0000000e },
{ 0x50, 0, 0, 0x0000001a },
{ 0x54, 0, 0, 0x000000f0 },
{ 0x74, 0, 0, 0x00000002 },
{ 0x7, 0, 0, 0x00000009 },
{ 0x60, 0, 0, 0x00000005 },
{ 0x1d, 1, 0, 0x00000000 },
{ 0x6, 0, 0, 0x00040000 },
{ 0x6, 0, 0, 0x00000000 },
};


static void print_usage(void)
{
  printf("Usage: pk-client <cmd>\n"
         " cmd := { start | stop | add } \n");
  exit(1);
}


int pk_filter_send_simple_cmd(pkfilter_cmd_t cmd_num, struct nl_sock* sk, pk_client_cmd_t* sub_cmd) {
  int err;
  struct nl_msg *msg;
  pkfilter_cmd_t cmd;
  pkfilter_msg_config_cmd_t* config_cmd;
  int cmd_size = sizeof(pkfilter_msg_config_cmd_t);
  
  if(sub_cmd!=NULL) {
    cmd_size += sub_cmd->size;
  }
  
  config_cmd = malloc(cmd_size);    
  
  msg = nlmsg_alloc_simple(NETLINK_PK_FILTER,0);
  if(!msg)
    return -1;
  
  config_cmd->command = cmd_num;

  if(sub_cmd!=NULL){
    config_cmd->len = sub_cmd->size;
    memcpy(&(config_cmd->data[0]),sub_cmd,sub_cmd->size);
  }
  
  nlmsg_append(msg, config_cmd, cmd_size, NLMSG_ALIGNTO);
  
  err = nl_send_auto_complete(sk, msg);
  nl_wait_for_ack(sk);  
 errout:
  nlmsg_free(msg);
  return err;    
}

int pk_filter_send_bpf(struct nl_sock* sk, enum pk_rule_type rt, struct sock_filter* sf)
{
  int err;
  pkfilter_msg_add_bpf_filter_cmd_t* cmd_msg ;
  int num = sizeof(sf) / sizeof(struct sock_filter);
  int code_size = sizeof(struct sock_filter) * num;  
  int msg_size = sizeof(pkfilter_msg_add_bpf_filter_cmd_t) + code_size;  
  struct nl_msg * nl_msg;
  
  cmd_msg = malloc(msg_size);
  
  nl_msg = nlmsg_alloc_simple(NETLINK_PK_FILTER,0);
  if(!nl_msg) {
    return -1;
  }
  
  cmd_msg->command =  rt;
  cmd_msg->len = num;
  memcpy(cmd_msg->data,sf,code_size);
  
  nlmsg_append(nl_msg,cmd_msg,msg_size, NLMSG_ALIGNTO);
  err  = nl_send_auto_complete(sk,nl_msg);
  nl_wait_for_ack(sk);
 errout:
  nlmsg_free(nl_msg);
  free(cmd_msg);
  return err;  
}

pk_client_cmd_t* parse_add_cmd(char* str_cmd){
  pk_client_cmd_t* cmd;
  
  char* ip = "192.168.1.75";
  int ip_len = strlen(ip);
  int attr_size = sizeof(pk_client_attr_t)+ip_len;
  int cmd_size = attr_size+sizeof(pk_client_cmd_t);
  
  cmd = malloc(cmd_size);
  cmd->type = PK_LOG_HDR;
  cmd->size = cmd_size;
  
  // Command Attributes
  cmd->nattr = 1;
  cmd->attrs[0].type = PK_AT_DST;
  cmd->attrs[0].nval = ip_len;
  memcpy(cmd->attrs[0].val,ip, ip_len);
  return cmd;
}


int main(int argc, char* argv[])
{
  struct nl_sock* sk;
  int err;
  char* subcmd = argv[1];
  
  if (argc < 2 || !strcmp(argv[1], "-h"))
    print_usage();
  
  if (!(sk = nl_socket_alloc())){
    exit(-1);
  }

  if ((err = nl_connect(sk, NETLINK_PK_FILTER)) < 0){
    fprintf(stderr,"No protocol handler for pk_filter installed \n");
    return err;
  }
  
  if(strcmp(subcmd,"start") == 0) {
    pk_filter_send_simple_cmd(PK_FILTER_CMD_START,sk,NULL);
  } else if (strcmp(subcmd,"stop") == 0) {
    pk_filter_send_simple_cmd(PK_FILTER_CMD_STOP,sk,NULL);
  } else if(strcmp(subcmd,"add") == 0) {    
    pk_filter_send_simple_cmd(PK_FILTER_CMD_ADD,sk,parse_add_cmd(subcmd));
  }else if(strcmp(subcmd,"bpf") == 0) {
    pk_filter_send_bpf(sk,PK_LOG_HDR, tcp_filter);
  }
  
  return 0;
}
