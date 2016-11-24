#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <stdbool.h>
#include <pthread.h>
 
#include <curl/curl.h>

#include "common.h"
#include "pstring.h"
#include "wsht_talk.h"
#include "conf.h"
#include "util.h"
#include "debug.h"

extern W_process_info p_infos[];

static size_t
AuthCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  pstr_t *pstr = (pstr_t *)userp;
  char *readbuf = (char*)contents; 
  if(realsize > 0){
    readbuf[realsize] = '\0';
    pstr_cat(pstr, readbuf);
    debug(LOG_DEBUG, "Read %d bytes", realsize);
  } 
  return realsize;
}

bool auth_server_request(const char* get_url, pstr_t *response)
{

  CURL *curl_handle;
  CURLcode res;
  bool is_ok=false;

  curl_global_init(CURL_GLOBAL_ALL);
  /* init the curl session */ 
  curl_handle = curl_easy_init();
  /* specify URL to get */ 
  curl_easy_setopt(curl_handle, CURLOPT_URL, get_url);
  /* send all data to this function  */ 
  curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, AuthCallback);
  /* we pass our 'chunk' struct to the callback function */ 
  curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)response);
  /* some servers don't like requests that are made without a user-agent
     field, so we provide one */ 
  curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "libcurl-agent/1.0");
  /* get it! */ 
  res = curl_easy_perform(curl_handle);
  /* check for errors */ 
  if(res != CURLE_OK) {
    fprintf(stderr, "curl_easy_perform() failed: %s\n",
            curl_easy_strerror(res));
  }
  else {
    /*
     * Now, our chunk.memory points to a memory block that is chunk.size
     * bytes big and contains the remote file.
     *
     * Do something nice with it!
     */ 
    is_ok=true;
    debug(LOG_DEBUG, "HTTP Response from Server: [%s]", response->buf);
  }
  /* cleanup curl stuff */ 
  curl_easy_cleanup(curl_handle);
  /* we're done with libcurl, so clean it up */ 
  curl_global_cleanup();
 
  return is_ok;
}

int authenticate_client(W_remote_conf *ret_conf)
{
    //W_remote_conf ret_conf;
    W_local_conf local_conf;
    
    s_config *config = config_get_config();
    char buf[MAX_BUF]={0};
    char *tmp,*p;
	int i=0;
    //pstr need to be freed
    pstr_t *response = pstr_new();
    char *res = NULL; // ----> pstr_t-->buf above, needed to be free    

    t_auth_serv *auth_server = NULL;
    auth_server = get_auth_server();
    
    ret_conf->authcode = AUTH_ERROR;
    local_conf.mac=config->gw_id;
    local_conf.local_ip=config->gw_address;
    local_conf.vpn_ip="0.0.0.0";
    local_conf.Co="WSHT";    

    snprintf(buf, (sizeof(buf) - 1),"http://%s%s%smac=%s&local_ip=%s&vpn_ip=%s&Co=%s",
        auth_server->authserv_hostname,
		auth_server->authserv_path,	
        auth_server->authserv_auth_script_path_fragment,
        local_conf.mac,local_conf.local_ip,local_conf.vpn_ip,local_conf.Co);
    printf("Get == %s \n", buf);

    if(auth_server_request(buf, response)){
	    res = pstr_to_string(response);
		if ((tmp = strstr(res, "Auth: "))) {
			if (sscanf(tmp, "Auth: %d\n", (int *)&ret_conf->authcode) == 1) {
				debug(LOG_INFO, "Auth server returned authentication code %d", ret_conf->authcode);
			} else {
				debug(LOG_WARNING, "Auth server did not return expected authentication code");
				free(res);
				return -1;
			}
	    }
		if ((tmp = strstr(res, "Function: "))) {
			if (sscanf(tmp, "Function: %d\n", (int *)&ret_conf->func) == 1) {
				debug(LOG_INFO, "Auth server returned Function code %d", ret_conf->func);
			} else {
				debug(LOG_WARNING, "Auth server did not return expected Function code");
				free(res);
				return -1;
			}
		}
		if ((tmp = strstr(res, "Cam_nums: "))) {
			if (sscanf(tmp, "Cam_nums: %d\n", (int *)&ret_conf->cam_nums) == 1) {
				debug(LOG_INFO, "Auth server returned Cam_nums %d", ret_conf->cam_nums);
			} else {
				debug(LOG_WARNING, "Auth server did not return expected Cam_nums");
				free(res);
				return -1;
			}
		}
		if ((tmp = strstr(res, "Rtsp: "))) {
			if (sscanf(tmp, "Rtsp: %s\n", buf) == 1) {
				debug(LOG_INFO, "Auth server returned Rtsp: %s", buf);
				//i=0-3,rtsp_url now support 4 cams
				p=strtok(buf,",");
				if(p)stpcpy(ret_conf->rtsp_url[0],p);
				else stpcpy(ret_conf->rtsp_url[0],buf);
				
				while((p=strtok(NULL,","))&& i<3){
					i++;
					stpcpy(ret_conf->rtsp_url[i],p);
				}
			} else {
				debug(LOG_WARNING, "Auth server did not return expected Rtsp Url");
				free(res);
				return -1;
			}
		}
    }
    else{
		///////////////////////error handler
		debug(LOG_WARNING, "Auth server did not response correctly");
		return -2;
    }
    if(res)free(res);
    switch (ret_conf->authcode) {

    case AUTH_ERROR:
        /* Error talking to central server */
        debug(LOG_ERR, "Got ERROR from central server authenticating");
        break;	
    case AUTH_DENIED:
        /* Central server said invalid token */
        debug(LOG_INFO, "Got DENIED from central server authenticating");
        break;
    case AUTH_ALLOWED:
        /* Logged in successfully as a regular account */
        debug(LOG_INFO, "Got ALLOWED from central server authenticating");
    	return 0;
    default:
        debug(LOG_WARNING,"I don't know what the validation code %d means", ret_conf->authcode);
        break;
    }
    return 1;
}

/** Post infos to server periodly
 *  in: W_local_infos*
 *  
 *  return: true/false
 */
bool post_server_infos(const char* post_url, W_local_infos *infos, pstr_t *response){

  CURL *curl;
  CURLcode res;
  int i;
  bool is_ok=false;
  char buffer[64];
  char name[16];
  curl_global_init(CURL_GLOBAL_ALL);  

  struct curl_httppost *formpost=NULL;
  struct curl_httppost *lastptr=NULL;
  struct curl_slist *headerlist=NULL;
  static const char buf[] = "Expect:";

  /* Fill in the file upload field. This makes libcurl load data from
     the given file name when curl_easy_perform() is called. */
  curl_formadd(&formpost,
               &lastptr,
               CURLFORM_COPYNAME, "cam_image",
               CURLFORM_FILE, infos->image_path,
               CURLFORM_END);

  /* Fill in the filename field */
  curl_formadd(&formpost,
               &lastptr,
               CURLFORM_COPYNAME, "filename",
               CURLFORM_COPYCONTENTS, "info.jpg",
               CURLFORM_END);

  //for multi camera to work together
  for(i=1;i<P_NUMS;i++){
    snprintf(buffer,sizeof(buffer)-1,"%sinfo%d.jpg",DEFAULT_IMAGE_PATH,i); 
    if(access(buffer, NULL) == 0){
      sprintf(name,"cam_image%d",i);
      curl_formadd(&formpost,
               &lastptr,
               CURLFORM_COPYNAME, name,
               CURLFORM_FILE, buffer,
               CURLFORM_END);
      sprintf(name,"info%d.jpg",i);
      curl_formadd(&formpost,
               &lastptr,
               CURLFORM_COPYNAME, "filename",
               CURLFORM_COPYCONTENTS, name,
               CURLFORM_END);
    }
  }

  /* Fill in the submit field too, even if this is rarely needed */
  curl_formadd(&formpost,
               &lastptr,
               CURLFORM_COPYNAME, "device_id",
               CURLFORM_COPYCONTENTS, infos->device_id,
               CURLFORM_END);

  snprintf(buffer,sizeof(buffer)-1,"%u",infos->rtsp_status); 
  curl_formadd(&formpost,&lastptr,CURLFORM_COPYNAME, "rtsp_status", 
	       CURLFORM_COPYCONTENTS, buffer,
	       CURLFORM_END); 

  
  snprintf(buffer,sizeof(buffer)-1,"%u",infos->vpu_status); 
  curl_formadd(&formpost,&lastptr,CURLFORM_COPYNAME, "vpu_status", 
	       CURLFORM_COPYCONTENTS, buffer,
	       CURLFORM_END); 
  
  snprintf(buffer,sizeof(buffer)-1,"%u",infos->detect_status); 
  curl_formadd(&formpost,&lastptr,CURLFORM_COPYNAME, "detect_status", 
	       CURLFORM_COPYCONTENTS, buffer,
	       CURLFORM_END); 

  curl = curl_easy_init();

  /* initialize custom header list (stating that Expect: 100-continue is not
     wanted */
  headerlist = curl_slist_append(headerlist, buf);
  if(curl) {

    /* what URL that receives this POST */
    curl_easy_setopt(curl, CURLOPT_URL, post_url);
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

    /* send all data to this function  */
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, AuthCallback);

    /* we pass our 'chunk' struct to the callback function */
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)response);

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);
    curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);

    

    res = curl_easy_perform(curl);

    /* Check for errors */
    if(res != CURLE_OK) {
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(res));
    }
    else {
      /*
       * Now, our chunk.memory points to a memory block that is chunk.size
       * bytes big and contains the remote file.
       *
       * Do something nice with it!
       */
        is_ok=true;
        debug(LOG_DEBUG, "HTTP Response from Server: [%s]", response->buf);
    }

    /* always cleanup */
    curl_easy_cleanup(curl);

    /* then cleanup the formpost chain */
    curl_formfree(formpost);

    /* free slist */
    curl_slist_free_all (headerlist);
    }
    return is_ok;
}

/** Post warnings to server periodly
 *  in: W_local_infos*
 *  
 *  return: true/false
 */
bool post_server_warning(const char* post_url, W_local_infos *infos, pstr_t *response){

  CURL *curl;
  CURLcode res;
  bool is_ok=false;

  curl_global_init(CURL_GLOBAL_ALL);  

  struct curl_httppost *formpost=NULL;
  struct curl_httppost *lastptr=NULL;
  struct curl_slist *headerlist=NULL;
  static const char buf[] = "Expect:";

  /* Fill in the file upload field. This makes libcurl load data from
     the given file name when curl_easy_perform() is called. */
  curl_formadd(&formpost,
               &lastptr,
               CURLFORM_COPYNAME, "cam_image",
               CURLFORM_FILE, infos->image_path,
               CURLFORM_END);

  /* Fill in the filename field */
  curl_formadd(&formpost,
               &lastptr,
               CURLFORM_COPYNAME, "filename",
               CURLFORM_COPYCONTENTS, "warning.jpg",
               CURLFORM_END);

  /* Fill in the submit field too, even if this is rarely needed */
  curl_formadd(&formpost,
               &lastptr,
               CURLFORM_COPYNAME, "device_id",
               CURLFORM_COPYCONTENTS, infos->device_id,
               CURLFORM_END);

  curl = curl_easy_init();

  /* initialize custom header list (stating that Expect: 100-continue is not
     wanted */
  headerlist = curl_slist_append(headerlist, buf);
  if(curl) {

    /* what URL that receives this POST */
    curl_easy_setopt(curl, CURLOPT_URL, post_url);
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

    /* send all data to this function  */
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, AuthCallback);

    /* we pass our 'chunk' struct to the callback function */
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)response);

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);
    curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);

    

    res = curl_easy_perform(curl);

    /* Check for errors */
    if(res != CURLE_OK) {
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(res));
    }
    else {
      /*
       * Now, our chunk.memory points to a memory block that is chunk.size
       * bytes big and contains the remote file.
       *
       * Do something nice with it!
       */
        is_ok=true;
        debug(LOG_DEBUG, "HTTP Response from Server: [%s]", response->buf);
    }

    /* always cleanup */
    curl_easy_cleanup(curl);

    /* then cleanup the formpost chain */
    curl_formfree(formpost);

    /* free slist */
    curl_slist_free_all (headerlist);
    }
    return is_ok;
}

/** @internal
 * This function does the actual request.
 */
static void ping(void)
{
    char request[MAX_BUF];
    FILE *fh;
    int i;
    W_local_infos infos;
    unsigned long int sys_uptime = 0;
    unsigned int sys_memfree = 0;
    unsigned int rtsp_status,vpu_status,detect_status;
    float sys_load = 0;
    char *image_path=NULL;
    //pstr need to be freed
    pstr_t *response = pstr_new();
    char *res = NULL; // ----> pstr_t-->buf above, needed to be free 

    t_auth_serv *auth_server = NULL;
    auth_server = get_auth_server();
    s_config *config = config_get_config();
    static int authdown = 0;

	//init to default
    rtsp_status=DEFAULT_RTSP_STATUS;
    vpu_status=DEFAULT_VPU_STATUS;
    detect_status=DEFAULT_DETECT_STATUS;
    image_path=DEFAULT_INFO_IMAGE_PATH;
    for(i=0;i<P_NUMS;i++){
	if(-1 == p_infos[i].pid && p_infos[i].errcode == 102){
	    rtsp_status ^= (1u << i);
	}
    }
	
    debug(LOG_DEBUG, "Entering ping()");
    memset(request, 0, sizeof(request));
    /*
     * Populate uptime, memfree and load
     */
    if ((fh = fopen("/proc/uptime", "r"))) {
        if (fscanf(fh, "%lu", &sys_uptime) != 1)
            debug(LOG_CRIT, "Failed to read uptime");

        fclose(fh);
    }
    if ((fh = fopen("/proc/meminfo", "r"))) {
        while (!feof(fh)) {
            if (fscanf(fh, "MemFree: %u", &sys_memfree) == 0) {
                /* Not on this line */
                while (!feof(fh) && fgetc(fh) != '\n') ;
            } else {
                /* Found it */
                break;
            }
        }
        fclose(fh);
    }
    if ((fh = fopen("/proc/loadavg", "r"))) {
        if (fscanf(fh, "%f", &sys_load) != 1)
            debug(LOG_CRIT, "Failed to read loadavg");

        fclose(fh);
    }
    infos.sys_uptime = sys_uptime;
    infos.sys_memfree = sys_memfree;
    infos.sys_load = sys_load;
    infos.rtsp_status = rtsp_status;
    infos.vpu_status = vpu_status;
    infos.detect_status = detect_status;
    infos.device_id = config->gw_id;
    infos.image_path = image_path;
    snprintf(request, (sizeof(request) - 1),"http://%s%s%s",
        auth_server->authserv_hostname,
	auth_server->authserv_path,	
        auth_server->authserv_ping_script_path_fragment);
    debug(LOG_INFO, "Post infos === %s", request);    

    if(post_server_infos(request, &infos, response)){
        res = pstr_to_string(response);
        debug(LOG_INFO, "Post infos to server successful, return: %s", res);
    }
    else{
	debug(LOG_ERR, "Ping thread says: Post infos to server wrong");
    }
    if(res)free(res);
}


/** @internal
 * This function does the actual request.
 */
void post_warning(void)
{
    char request[MAX_BUF];
    FILE *fh;
    W_local_infos infos;
    unsigned long int sys_uptime = 0;
    unsigned int sys_memfree = 0;
    unsigned int rtsp_status,vpu_status,detect_status;
    float sys_load = 0;
    char *image_path=NULL;
    //pstr need to be freed
    pstr_t *response = pstr_new();
    char *res = NULL; // ----> pstr_t-->buf above, needed to be free 

    t_auth_serv *auth_server = NULL;
    auth_server = get_auth_server();
    s_config *config = config_get_config();
    static int authdown = 0;

	//init to default
    rtsp_status=DEFAULT_RTSP_STATUS;
    vpu_status=DEFAULT_VPU_STATUS;
    detect_status=DEFAULT_DETECT_STATUS;
    image_path=DEFAULT_WARNING_IMAGE_PATH;
	
    debug(LOG_DEBUG, "Entering warning()");
    memset(request, 0, sizeof(request));
    /*
     * Populate uptime, memfree and load
     */
    if ((fh = fopen("/proc/uptime", "r"))) {
        if (fscanf(fh, "%lu", &sys_uptime) != 1)
            debug(LOG_CRIT, "Failed to read uptime");

        fclose(fh);
    }
    if ((fh = fopen("/proc/meminfo", "r"))) {
        while (!feof(fh)) {
            if (fscanf(fh, "MemFree: %u", &sys_memfree) == 0) {
                /* Not on this line */
                while (!feof(fh) && fgetc(fh) != '\n') ;
            } else {
                /* Found it */
                break;
            }
        }
        fclose(fh);
    }
    if ((fh = fopen("/proc/loadavg", "r"))) {
        if (fscanf(fh, "%f", &sys_load) != 1)
            debug(LOG_CRIT, "Failed to read loadavg");

        fclose(fh);
    }
    infos.sys_uptime = sys_uptime;
    infos.sys_memfree = sys_memfree;
    infos.sys_load = sys_load;
    infos.rtsp_status = rtsp_status;
    infos.vpu_status = vpu_status;
    infos.detect_status = detect_status;
    infos.device_id = config->gw_id;
    infos.image_path = image_path;
    snprintf(request, (sizeof(request) - 1),"http://%s%s%s",
        auth_server->authserv_hostname,
	auth_server->authserv_path,	
        auth_server->authserv_ping_script_path_fragment);
    debug(LOG_INFO, "Post warning === %s", request);    

    if(post_server_warning(request, &infos, response)){
        res = pstr_to_string(response);
        debug(LOG_INFO, "Post warning to server successful, return: %s", res);
    }
    else{
	debug(LOG_ERR, "Wshtctl thread says: Post warning to server wrong");
    }
    if(res)free(res);
}
/** Launches a thread that periodically checks in with the wifidog auth server to perform heartbeat function.
@param arg NULL
@todo This thread loops infinitely, need a watchdog to verify that it is still running?
*/
void thread_ping(void *arg)
{
    pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
    pthread_mutex_t cond_mutex = PTHREAD_MUTEX_INITIALIZER;
    struct timespec timeout;

    while (1) {
        /* Make sure we check the servers at the very begining */
        debug(LOG_DEBUG, "Running ping()");
        ping();

        /* Sleep for config.checkinterval seconds... */
        timeout.tv_sec = time(NULL) + config_get_config()->checkinterval;
        timeout.tv_nsec = 0;

        /* Mutex must be locked for pthread_cond_timedwait... */
        pthread_mutex_lock(&cond_mutex);

        /* Thread safe "sleep" */
        pthread_cond_timedwait(&cond, &cond_mutex, &timeout);

        /* No longer needs to be locked */
        pthread_mutex_unlock(&cond_mutex);
    }
}
