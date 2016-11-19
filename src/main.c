#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include "debug.h"
#include "conf.h"
#include "wsht_talk.h"
#define MINIMUM_STARTED_TIME 1041379200 //from wifidog ping

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
    int status;
    pid_t rc;
    debug(LOG_DEBUG, "Handler for SIGCHLD called. Trying to reap a child");
    rc = waitpid(-1, &status, WNOHANG);
    debug(LOG_DEBUG, "Handler for SIGCHLD reaped child PID %d", rc);
}

/** Exits cleanly after cleaning up the firewall.  
 *  Use this function anytime you need to exit after firewall initialization.
 *  @param s Integer that is really a boolean, true means voluntary exit, 0 means error.
 */
void
termination_handler(int s)
{
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
    int result;
    pthread_t tid;
    s_config *config = config_get_config();
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
    
    authenticate_client();
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
