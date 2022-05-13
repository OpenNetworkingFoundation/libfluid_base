#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include <event2/thread.h>

#include "BaseOFTunDev.hh"

using namespace fluid_base;

BaseOFTunDev::BaseOFTunDev(int id, std::string devname, DevType devtype) {
    // Prepare libevent for threads
    // This will leave a small, insignificant leak for us.
    // See: http://archives.seul.org/libevent/users/Jul-2011/msg00028.html
    evthread_use_pthreads();
    // Ignore SIGPIPE so it becomes an EPIPE
    signal(SIGPIPE, SIG_IGN);

    this->id = id;
    this->devname = devname;
    this->devtype = devtype;
    this->evloop = new EventLoop(0);
}

BaseOFTunDev::~BaseOFTunDev() {
    delete this->evloop;
}

void* BaseOFTunDev::try_connect(void *arg){
    int sock, sk;
    struct ifreq ifr;
    int received = 0;
    bocType boctype = boc_OFMSG;

    BaseOFTunDev *bot = (BaseOFTunDev*) arg;

    if(bot->devtype == DEV_TUN) boctype = boc_TUN;
    if(bot->devtype == DEV_TAP) boctype = boc_TAP;

    /* Create the Tun Device */
    if ((sock = open("/dev/net/tun", O_RDWR)) < 0) {
        fprintf(stderr, "Error creating socket");
        return NULL;
    }
    memset(&ifr, 0, sizeof(ifr));
    /* Flags: IFF_TUN   - TUN device (no Ethernet headers)
    *        IFF_TAP   - TAP device
    *
    *        IFF_NO_PI - Do not provide packet information
    */
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if(bot->devtype == DEV_TUN) ifr.ifr_flags |= IFF_TUN;
    if(bot->devtype == DEV_TAP) ifr.ifr_flags |= IFF_TAP;
    if( strlen(bot->devname.c_str()) )
        strncpy(ifr.ifr_name, bot->devname.c_str(), IFNAMSIZ);

    if(ioctl(sock, TUNSETIFF, (void *) &ifr) < 0) {
        fprintf(stderr, "create tun/tap device %s failed.\n", bot->devname.c_str());
        close(sock);
        return NULL;
    }

    ioctl(sock, TUNSETNOCSUM, 1);

    BaseOFConnection* c = new BaseOFConnection(bot->id,
                                               bot,
                                               bot->evloop,
                                               sock,
                                               false, boctype);

    sk = socket(PF_INET, SOCK_DGRAM, 0);
    if(sk < 0) {
        fprintf(stderr, "open sk for link op failed.\n");
        return NULL;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, bot->devname.c_str(), IFNAMSIZ);
    if (ioctl(sk, SIOCGIFFLAGS, &ifr) < 0) {
        fprintf(stderr, "get tun/tap %s IFFLAGS failed.\n", bot->devname.c_str());
        close(sk);
        return NULL;
    }

    if(! (ifr.ifr_flags & IFF_UP)) {
        ifr.ifr_flags |= IFF_UP;
        if (ioctl(sk, SIOCSIFFLAGS, &ifr) < 0) {
            fprintf(stderr, "set tun/tap %s link up failed.\n", bot->devname.c_str());
            close(sk);
            return NULL;
        }
    }

    return NULL;
}

void BaseOFTunDev::start_conn(){
    pthread_create(&conn_t, NULL,
                      try_connect,
                       this);
}

bool BaseOFTunDev::start(bool block) {
    this->blocking = block;
    BaseOFTunDev::start_conn();
    if (not this->blocking) {
        pthread_create(&t,
                       NULL,
                       EventLoop::thread_adapter,
                       evloop);
    }
    else {
        evloop->run();
    }
    return true;
}

void BaseOFTunDev::free_data(void* data) {
    BaseOFConnection::free_data(data);
}

void BaseOFTunDev::stop() {
    pthread_cancel(this->conn_t);
    evloop->stop();
    if (not this->blocking) {
        pthread_join(t, NULL);
    }
}

void BaseOFTunDev::base_connection_callback(BaseOFConnection* conn, BaseOFConnection::Event event_type) {
    if (event_type == BaseOFConnection::EVENT_CLOSED) {
        delete conn;
    }
}

