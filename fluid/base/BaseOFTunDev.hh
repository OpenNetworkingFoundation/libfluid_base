/** @file */
#ifndef __BASEOFTUNDEV_HH__
#define __BASEOFTUNDEV_HH__

#include <pthread.h>

#include <string>

#include <fluid/base/EventLoop.hh>
#include <fluid/base/BaseOFConnection.hh>

using namespace fluid_base;

enum DevType {
        /** The tun type device or netif */
        DEV_TUN,
        /** The tap type device or netif */
        DEV_TAP,
        /** The device/tun type not supported yet */
        DEV_UNKNOWN
};

/**
A BaseOFTunDev manages the very basic functions of an OpenFlow tun/tap device. It
connects to a tun/tap device and wait for tunnel/tap traffic and connection events. It is an
abstract class that should be overriden by another class to provide OpenFlow
features.
*/
class BaseOFTunDev : public BaseOFHandler {
public:
    /**
    Create a BaseOFTunDev.

    @param port listen port
    @param nevloops number of event loops to run. Connections will be
                    attributed to event loops running on threads on a
                    round-robin fashion. The first event loop will listen for
                    new connections.
    */
    BaseOFTunDev(int id, std::string devname, DevType devtype);
    ~BaseOFTunDev();

    /**
    Start the device. It will create a tun/tap device with the devname and devtype declared in the
    constructor and wait for events, optionally blocking the calling thread
    until BaseOFTunDev::stop is called.

    @param block block the calling thread while the client is running
    */
    virtual bool start(bool block = false);

    virtual void start_conn();

    static void* try_connect(void* arg);

    /**
    Stop the device. It will close the connection and signal the event loop to
    stop running.

    It will eventually unblock BaseOFTunDev::start if it is blocking.
    */
    virtual void stop();


    virtual void base_connection_callback(BaseOFConnection* conn,
                                          BaseOFConnection::Event event_type);
    virtual void base_message_callback(BaseOFConnection* conn,
                                       void* data,
                                       size_t len) = 0;
    virtual void free_data(void* data);

private:
    int id;
    bool blocking;
    EventLoop* evloop;
    pthread_t t;
    pthread_t conn_t;

    std::string devname;
    DevType devtype;

};

#endif
