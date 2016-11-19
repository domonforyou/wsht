#ifndef _WSHT_TALK_H_
#define _WSHT_TALK_H_

typedef enum{
   FallDown_Detection=0,
   Fire_Detection,
   Smile_Detection,
   Total_Detection
}Function_Code;

typedef enum{
   AUTH_ERROR = -1,
   AUTH_DENIED = 0,
   AUTH_ALLOWED = 1
}Auth_Code;

typedef enum{
   W_UNKNOWN_ERROR = -1,
   W_FMT_ERR = 0,
   W_OKAY = 1,
   W_UNAUTHORIZED = 2
}Ret_Code;

typedef struct _local_conf{
    char *mac;
    char *local_ip;
    char *vpn_ip;
    char *Co;
}W_local_conf;

typedef struct _remote_conf{
    Auth_Code authcode;
    int cam_nums;
    Function_Code func;
    char rtsp_url[4][256];
}W_remote_conf;


void authenticate_client();
#endif
