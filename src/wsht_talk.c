#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <stdbool.h>
 
#include <curl/curl.h>

#include "common.h"
#include "pstring.h"
#include "wsht_talk.h"
#include "conf.h"
#include "debug.h"


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

bool auth_server_request(const char* get_url, pstr_t *response, W_remote_conf *ret_conf)
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

void
authenticate_client()
{
    W_remote_conf ret_conf;
    W_local_conf local_conf;
    
    s_config *config = config_get_config();
    char buf[MAX_BUF]={0};
    
    //pstr need to be freed
    pstr_t *response = pstr_new();
    char *retval = NULL; // ----> pstr_t-->buf above, needed to be free    

    t_auth_serv *auth_server = NULL;
    auth_server = get_auth_server();
    
    ret_conf.authcode = AUTH_ERROR;
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

    if(auth_server_request(buf, response, &ret_conf)){
	retval = pstr_to_string(response);
    }
    else{
	///////////////////////error handler
    }
    printf("Response == %s \n", retval);
    free(retval);
}
