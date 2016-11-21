#ifndef _WSHT_TALK_H_
#define _WSHT_TALK_H_

#define DEFAULT_RTSP_STATUS 0x0F
#define DEFAULT_VPU_STATUS 0x0F
#define DEFAULT_DETECT_STATUS 0x0F
#define DEFAULT_INFO_IMAGE_PATH "/tmp/wsht/info.jpg"
#define DEFAULT_WARNING_IMAGE_PATH "/tmp/wsht/warning.jpg"

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

typedef struct _local_infos{
	unsigned long int sys_uptime;
	unsigned int sys_memfree;
	float sys_load;
	unsigned int rtsp_status;
	unsigned int vpu_status;
	unsigned int detect_status;
	char *device_id;
	char *image_path;
}W_local_infos;
//auth myself
int authenticate_client(W_remote_conf *ret_conf);
void thread_ping(void *arg);
#endif
