// You will build this in project part B - this is merely a
// stub that does nothing but integrate into the stack

// For project parts A and B, an appropriate binary will be
// copied over as part of the build process



#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>


#include <iostream>

#include "Minet.h"
#include "ip.h"
#include "tcp.h"
#include "packet.h"

using namespace std;

enum State = {CLOSED, LISTEN, SYN_RCVD, SYN_SENT, ESTABLISHED, CLOSE_WAIT,
LAST_ACK, FIN_WAIT_1, FIN_WAIT_2, CLOSING, TIME_WAIT};

bool conductStateTransition (State current, State next, TCPState * connection) {
  if (!connection->isInState(current)) return false;
  else {
    connection->setStateTo(next);
    return true;
  }
}

struct ClientInfo {

  struct IPAddress myIP;
  int portNum;

  ClientInfo (const struct IPAddress * ip, int port) {
    myIP = IPAddress (ip);
    portNum = port;
  }

}

bool beginTransfer(TCPState * connection, Packet pkt) {

}

bool parsePacket () {

}

Packet getPacket (const MinetHandle &handle) {
  Packet * pk = calloc(sizeof(Packet));
  if (MinetReceive(handle, pk) > 0) return pk;
  else return NULL; //throw error here?
}

bool resetHandshake (TCPState * connection, Packet pkt) {
  //received reset, set handshake back to original state
}

bool sendSynAck (TCPState * connection, Packet pkt) {

}

bool transferData(TCPState * connection, Packet pkt) {

}

bool closeWait (TCPState * connection, Packet pkt) {

}

 bool handlePacket (TCPState * connection, Packet pkt) {
  //Responds to an IP event based on the packet type and current connection state
  State current = connection->getState();

  switch (current) {

    case (LISTEN) {
      return IS_SYN(pkt) ? sendSynAck(connection, pkt) : false;
    }

    case (SYN_RCVD) {
      if (IS_ACK(pkt)) return beginTransfer(connection, pkt);
      else if (IS_RST(pkt)) return resetHandshake(connection, pkt);
      else return false;
    }

    case (SYN_SENT) {
      if (IS_SYN(pkt)) { return IS_ACK(pkt) ? beginTransfer(connection, pkt) : sendSynAck(connection, pkt); }
      else return false;
    }
    case (ESTABLISHED) {
      return IS_FIN(pkt) ? closeWait(connection, pkt) : transferData(connnection, pkt);
    }

    case (FIN_WAIT_1) {
     return IS_FIN(pkt) ? (IS_ACK(pkt) ? timeWait(connection, pkt) : initiateClose(connection, pkt)) : (IS_ACK(pkt) ? finWait2(connection, pkt) : false);
    }

    case (FIN_WAIT_2) {
      return IS_FIN(pkt) ? timeWait(connection, pkt) : false;
    }

    case (CLOSING) {
      return IS_ACK(pkt) ? timeWait(connection, pkt) : false;
    }

    default { return false; }
    
    }
  }
}

struct TCPState {
    // need to write this
    std::ostream & Print(std::ostream &os) const {
	     os << "TCPState()" ;
	     return os;
    }

    private State currentState;

    bool isInState (State check) { return check == currentState; }

    void setStateTo (State newState) { currentState = newState; }

    private clientInfo client;

    State getState () { return currentState; }

};

bool listen(TCPState * connection, MinetHandle * ipmux, MinetHandle * minSock) {
  //Waits to receive syn or be asked to send data, sends syn-ack to client

  State deisred = CLOSED;
  if (!connection->isInState(CLOSED)) return false;
  else connection->setStateTo(LISTEN);

}

bool activeOpen(TCPState * connection) {
  //Actively opens a connection to a client
  if ( !(connection->isInState(CLOSED) || connection->isInState(LISTED)) ) return false;


}

bool passiveOpen (TCPState * connection, MinetHandle * ipmux, MinetHandle * sock ) {
  //Passively opens a connection
  listen(connection, ipmux, );

  conductStateTransition(CLOSED, LISTEN, connection);
}

bool receiveSyn(TCPState * connection, MinetHandle * ipmux) {

}


int main(int argc, char * argv[]) {
    MinetHandle mux;
    MinetHandle sock;

    ConnectionList<TCPState> clist;

    MinetInit(MINET_TCP_MODULE);


    //This is a minet handle, call recv to get packets
    mux = MinetIsModuleInConfig(MINET_IP_MUX) ?
	MinetConnect(MINET_IP_MUX) :
	MINET_NOHANDLE;

    sock = MinetIsModuleInConfig(MINET_SOCK_MODULE) ?
	MinetAccept(MINET_SOCK_MODULE) :
	MINET_NOHANDLE;

    if ( (mux == MINET_NOHANDLE) &&
	 (MinetIsModuleInConfig(MINET_IP_MUX)) ) {

	MinetSendToMonitor(MinetMonitoringEvent("Can't connect to ip_mux"));

	return -1;
    }

    if ( (sock == MINET_NOHANDLE) &&
	 (MinetIsModuleInConfig(MINET_SOCK_MODULE)) ) {

	MinetSendToMonitor(MinetMonitoringEvent("Can't accept from sock_module"));

	return -1;
    }

    cerr << "tcp_module STUB VERSION handling tcp traffic.......\n";

    MinetSendToMonitor(MinetMonitoringEvent("tcp_module STUB VERSION handling tcp traffic........"));

    MinetEvent event;
    double timeout = 1;

    while (MinetGetNextEvent(event, timeout) == 0) {

	if ((event.eventtype == MinetEvent::Dataflow) &&
	    (event.direction == MinetEvent::IN)) {

	    if (event.handle == mux) {
		      // ip packet has arrived! (PASSIVE DATAFLOW)
          handlePacket(connection, getPacket(&mux));
	    }

	    if (event.handle == sock) {
		      // socket request or response has arrived (APP LAYER REQUEST)
	    }
	}

	if (event.eventtype == MinetEvent::Timeout) {
	    // timeout ! probably need to resend some packets
	}

    }

    MinetDeinit();

    return 0;
}
