#ifndef PK_NETLINK_H
#define PK_NETLINK_H

// structures shared with kernel module

typedef enum pkfilter_cmd {
  PK_FILTER_CMD_STOP = 0,
  PK_FILTER_CMD_START = 1,
  PK_FILTER_CMD_ADD  = 2,
} pkfilter_cmd_t;

#define PK_NL_CMD_MAX 3

enum pk_rule_type {
  PK_ACCEPT,
  PK_DROP,
  PK_LOG,
  PK_LOG_HDR
};

enum pk_attr_type {
  PK_AT_SRC  = 0,
  PK_AT_DST = 1,
  PK_AT_PROTO = 2,
  PK_AT_MAX = 3
};

typedef struct pk_client__attr {
  int type;
  int nval;
  char val[];
} pk_client_attr_t;

typedef struct pk_client_cmd {
  int size;
  int type;
  int nattr;
  pk_client_attr_t attrs[];  
} pk_client_cmd_t;


typedef struct pkfilter_msg_config_cmd {
  u_int8_t	command;	/* pkfilter_msg_config_cmds */
  u_int8_t      len;
  pk_client_cmd_t data[];
} __attribute__ ((packed)) pkfilter_msg_config_cmd_t;

#endif
