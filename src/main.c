#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include "debug.h"
#include "conf.h"
#include "util.h"
#include "wdctl_thread.h"
#include "wsht_talk.h"
#define MINIMUM_STARTED_TIME 1041379200 //from wifidog ping
#define P_NUMS 4
#define WSHT_DETECTOR_APP "./wsht_detector"

static pthread_t tid_ping = 0;
static W_process_info p_infos[P_NUMS]={0};
static int p_status = 0;
time_t started_time = 0;
/**@internal
 * @brief Handles SIGCHLD signals to avoid zombie processes
 *
 * When a child process exits, it causes a SIGCHLD to be sent to the
 * process. This handler catches it and reaps the child process so it
 * can exit. Otherwise we'd get zombie processes.
 */
void
sigchld_handler(int s)
{
    int i,status;
    pid_t rc;
    debug(LOG_INFO, "Handler for SIGCHLD called. Trying to reap a child");
    rc = waitpid(-1, &status, WNOHANG);
    debug(LOG_INFO, "Handler for SIGCHLD reaped child PID %d", rc);
    p_status = 1;    
    for(i=0;i<P_NUMS;i++){
	if(rc == p_infos[i].pid){
	    debug(LOG_INFO, "Child %d Is Dead", rc);
            p_infos[i].pid = -1;
	}
    }
}

/** Exits cleanly after cleaning up the firewall.  
 *  Use this function anytime you need to exit after firewall initialization.
 *  @param s Integer that is really a boolean, true means voluntary exit, 0 means error.
 */
void
termination_handler(int s)
{
	pthread_t self = pthread_self();
	if (tid_ping && self != tid_ping) {
        debug(LOG_INFO, "Explicitly killing the ping thread");
        pthread_kill(tid_ping, SIGKILL);
    }
    debug(LOG_NOTICE, "Exiting...");
    exit(s == 0 ? 1 : 0);
}
/** @internal 
 * Registers all the signal handlers
 */
static void
init_signals(void){

    struct sigaction sa;

    debug(LOG_DEBUG, "Initializing signal handlers");

    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        debug(LOG_ERR, "sigaction(): %s", strerror(errno));
        exit(1);
    }

    /* Trap SIGPIPE */
    /* This is done so that when libhttpd does a socket operation on
     * a disconnected socket (i.e.: Broken Pipes) we catch the signal
     * and do nothing. The alternative is to exit. SIGPIPE are harmless
     * if not desirable.
     */
    sa.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &sa, NULL) == -1) {
        debug(LOG_ERR, "sigaction(): %s", strerror(errno));
        exit(1);
    }

    sa.sa_handler = termination_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;

    /* Trap SIGTERM */
    if (sigaction(SIGTERM, &sa, NULL) == -1) {
        debug(LOG_ERR, "sigaction(): %s", strerror(errno));
        exit(1);
    }

    /* Trap SIGQUIT */
    if (sigaction(SIGQUIT, &sa, NULL) == -1) {
        debug(LOG_ERR, "sigaction(): %s", strerror(errno));
        exit(1);
    }

    /* Trap SIGINT */
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        debug(LOG_ERR, "sigaction(): %s", strerror(errno));
        exit(1);
    }
}

/**@internal
 * Main execution loop 
 */
static void
main_loop(void){
    int result,i=0;
    pthread_t tid;
    W_remote_conf conf;
    s_config *config = config_get_config();
    char *cmd;
    int pid[4]={0};
    //request *r;
    void **params;

    /* Set the time when app started */
    if (!started_time) {
        debug(LOG_INFO, "Setting started_time");
        started_time = time(NULL);
    } else if (started_time < MINIMUM_STARTED_TIME) {
        debug(LOG_WARNING, "Detected possible clock skew - re-setting started_time");
        started_time = time(NULL);
    }

    /* save the pid file if needed */
    if ((!config) && (!config->pidfile))
        save_pid_file(config->pidfile);

    /* If we don't have the Gateway IP address, get it. Can't fail. */
    if (!config->gw_address) {
        debug(LOG_INFO, "Finding IP address of %s", config->gw_interface);
        if ((config->gw_address = get_iface_ip(config->gw_interface)) == NULL) {
            debug(LOG_ERR, "Could not get IP address information of %s, exiting...", config->gw_interface);
            exit(1);
        }
        debug(LOG_INFO, "%s = %s", config->gw_interface, config->gw_address);
    }

    /* If we don't have the Gateway ID, construct it from the internal MAC address.
     * "Can't fail" so exit() if the impossible happens. */
    if (!config->gw_id) {
        debug(LOG_INFO, "Finding MAC address of %s", config->gw_interface);
        if ((config->gw_id = get_iface_mac(config->gw_interface)) == NULL) {
            debug(LOG_ERR, "Could not get MAC address information of %s, exiting...", config->gw_interface);
            exit(1);
        }
        debug(LOG_INFO, "%s = %s", config->gw_interface, config->gw_id);
    }
    //auth ok
    if(!authenticate_client(&conf)){
	for(i=0;i<conf.cam_nums;i++){
            safe_asprintf(&cmd, "%s %s -f %d", WSHT_DETECTOR_APP, conf.rtsp_url[i], conf.func);
	    p_infos[i].pid = execute_without_waiting(cmd, 0);
            strcpy(p_infos[i].cmd, cmd);
	}
	/* Start control thread */
        result = pthread_create(&tid, NULL, (void *)thread_wdctl, (void *)safe_strdup(config->wdctl_sock));
        if (result != 0) {
            debug(LOG_ERR, "FATAL: Failed to create a new thread (wdctl) - exiting");
            termination_handler(0);
        }
        pthread_detach(tid);
	/* Start heartbeat thread */
        result = pthread_create(&tid_ping, NULL, (void *)thread_ping, NULL);
        if (result != 0) {
            debug(LOG_ERR, "FATAL: Failed to create a new thread (ping) - exiting");
            termination_handler(0);
        }
        pthread_detach(tid_ping);
	while(1){
            sleep(30);
            debug(LOG_INFO, "I am the master, i am alive");
            if(p_status){
		p_status=0;
    		for(i=0;i<P_NUMS;i++){
		    if(-1 == p_infos[i].pid){
	    	    	debug(LOG_INFO, "Child : %s", p_infos[i].cmd);
            	    	p_infos[i].pid = execute_without_waiting(p_infos[i].cmd, 0);
		        sleep(10);
		    }
    		}
	    }
        }
    }
    else{
        debug(LOG_ERR, "Auth myself failed");
    }
	
}

int main(int argc, char **argv){

    s_config *config = config_get_config();
    config_init();

    parse_commandline(argc, argv);

    /* Initialize the config */
    config_read(config->configfile);
    config_validate();
    init_signals();
    
    if (config->daemon) {

        debug(LOG_INFO, "Forking into background");

        switch (safe_fork()) {
        case 0:                /* child */
            setsid();
            main_loop();
            break;

        default:               /* parent */
            exit(0);
            break;
        }
    } else {
        main_loop();
    }
}
