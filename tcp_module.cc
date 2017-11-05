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
#include "tcpstate.h"

using namespace std;


/*struct TCPState {
    // need to write this
    std::ostream & Print(std::ostream &os) const {
	     os << "TCPState()" ;
	     return os;
    }

    State currentState;

    MinetHandle sockFD, ipMux;

    bool isInState (State check) { return check == currentState; }

    void setStateTo (State newState) { currentState = newState; }

    unsigned short srcPort = -1;
    struct IPAddress srcIP;
    unsigned short destPort = -1; //Initial invalid value
     struct IPAddress destIP;

    bool checkPacketSrc (Packet *p) {
      if (srcPort < 0 || destPort < 0) return false;
      Header::IPHeader *ipHead = p->PopFrontHeader();
      Header::TCPHeader *tcpHead = p->PopBackHeader();
      unsigned short *portCache = calloc(sizeof(unsigned short));

      tcpHead->GetSourcePort(portCache);
      if (*portCache != srcPort) return false;
      tcpHead->GetDestPort(portCache);
      if (*portCache != destPort) return false;

      struct IPAddress * ipCache = calloc(sizeof(IPAddress));
      ipHead->GetSourceIP(ipCache);
      if (*ipCache != srcIP) return false;
      ipHead->GetDestIP(ipCache);
      if(*ipCache !- destIP) return false;
      //TODO: Checksums, seq nums, etc.

      //Passed all tests!
      return true;
    }

    //Packet inTransit?

    State getState () { return currentState; }

};

bool conductStateTransition (State current, State next, TCPState * connection) {
  if (!connection->isInState(current)) return false;
  else {
    connection->setStateTo(next);
    return true;
  }
}

bool beginTransfer(TCPState * connection, Packet pkt) {
  // SetSourcePort(&(connection->srcPort), pkt);
  // SetDestPort(&(connection->destPort), pktIP);
  //Officially enter data transfer state
  //Send ack first!
}

bool concludeHandshake(TCPState * connection, Packet pkt) {
  //Send ack! wait for data transfer
  Packet p;
  unsigned short len;
  bool checksumok;
  MinetReceive(connection->ipMux, p);
  p.ExtractHeaderFromPayload<TCPHeader>(8); //Why 8? This might need to change
  TCPHeader tcph;
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
  connection->setStateTo()

}

bool sendSynAck (TCPState * connection, Packet pkt) {
  //Store IP info? Or do this at begin connection
}

bool transferData(TCPState * connection, Packet pkt) {

}

bool closeWait (TCPState * connection, Packet pkt) {

}

 bool handlePacket (TCPState * connection, Packet pkt) {
  //Responds to an IP event based on the packet type and current connection state
  State current = connection->getState();
  //Get header from packet
  Header::IPHeader ipHead = pkt.PopFrontHeader();
  Header::TCPHeader tcpHead = pkt.PopBackHeader();

  char l;
  int headlen = tcpHead.GetHeaderLen(&l);
  unsigned char *flags = malloc(l);
  tcpHead.GetFlags(flags);

  switch (current) {

    case (LISTEN) {
      return IS_SYN(flags) ? sendSynAck(connection, pkt) : false;
    }

    case (SYN_RCVD) {
      if (IS_ACK(flags)) return beginTransfer(connection, pkt);
      else if (IS_RST(flags)) return resetHandshake(connection, pkt);
      else return false;
    }

    case (SYN_SENT) {
      if (IS_SYN(flags)) { return IS_ACK(flags) ? concludeHandshake(connection, pkt) : sendSynAck(connection, pkt); }
      else return false;
    }
    case (ESTABLISHED) {
      return IS_FIN(flags) ? closeWait(connection, pkt) : transferData(connnection, pkt);
    }

    case (FIN_WAIT_1) {
     return IS_FIN(flags) ? (IS_ACK(flags) ? timeWait(connection, pkt) : initiateClose(connection, pkt)) : (IS_ACK(flags) ? finWait2(connection, pkt) : false);
    }

    case (FIN_WAIT_2) {
      return IS_FIN(flags) ? timeWait(connection, pkt) : false;
    }

    case (CLOSING) {
      return IS_ACK(flags) ? timeWait(connection, pkt) : false;
    }

    default { return false; }

    }
  }


bool handleAppRequest(TCPState * connection, MinetHandle * sock) {
  //TODO: Handle app requests!!! (TCP-Socket layer interface)
  return false;
}


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

} */ //TODO: Fix all

Packet makePacket(SockRequestResponse r) {
    unsigned bytes = MIN_MACRO(TCP_MAXIMUM_SEGMENT_SIZE, r.data.GetSize());
    Packet pack(r.data.ExtractFront(bytes));
    IPHeader ih;
    ih.SetProtocol(IP_PROTO_TCP);
    ih.SetSourceIP(r.connection.src);
    ih.SetDestIP(r.connection.dest);
    ih.SetTotalLength(bytes+TCP_HEADER_BASE_LENGTH+IP_HEADER_BASE_LENGTH);
    pack.PushFrontHeader(ih);
    TCPHeader th;
    th.SetSourcePort(r.connection.srcport, pack);
    th.SetDestPort(r.connection.destport, pack);
    th.SetLength(TCP_HEADER_BASE_LENGTH+bytes, pack);
    pack.PushBackHeader(th);
    return pack;
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
		    // ip packet has arrived!
            Packet p;
            unsigned short len;
            bool checksumok;
            MinetReceive(mux, p);
            cerr << "Packet: " << endl;  //DEBUGGING
            cerr << p << endl;          //DEBUGGING
            TCPHeader tcph = p.PopBackHeader();
            checksumok = tcph.IsCorrectChecksum(p);
            IPHeader iph = p.PopFrontHeader();
            Connection c;
            // note that this is flipped around because
            // "source" is interepreted as "this machine"
            iph.GetDestIP(c.src);
            iph.GetSourceIP(c.dest);
            iph.GetProtocol(c.protocol);
            tcph.GetDestPort(c.srcport);
            tcph.GetSourcePort(c.destport);
            ConnectionList<TCPState>::iterator cs = clist.FindMatching(c);
            if (cs != clist.end()) {
                iph.GetTotalLength(len);
                unsigned char headLen;
                tcph.GetHeaderLen(headLen);
                len -= headLen;
                Buffer &data = p.GetPayload().ExtractFront(len);
                SockRequestResponse write(WRITE, (*cs).connection, data, len, EOK);
                if (!checksumok) {
                    MinetSendToMonitor(MinetMonitoringEvent("forwarding packet to sock even though checksum failed"));
                }
                MinetSend(sock, write);
            } else {
                MinetSendToMonitor(MinetMonitoringEvent("Unknown port"));
            }
	    }

	    if (event.handle == sock) {
    		// socket request or response has arrived
            SockRequestResponse req;
            MinetReceive(sock, req);
            cerr << "Sock request: " << endl;           //DEBUGGING
            cerr << req << endl;         //DEBUGGING
            ConnectionToStateMapping<TCPState> connectstate;
            Connection c;
            TCPState curr;
            switch (req.type) {
                case CONNECT:
                {
                    //active open to remote
                    break;
                }
                case ACCEPT:
                {
                    //passive open from remote
                    break;
                }
                case WRITE:
                {
                    //send TCP data
                    ConnectionList<TCPState>::iterator cs = clist.FindMatching(req.connection);
                    connectstate = *cs;
                    c = connectstate.connection;
                    curr = connectstate.state;
                    break;
                }
                case FORWARD:
                {
                    //ignore
                    break;
                }
                case CLOSE:
                {
                    break;
                }
                case STATUS:
                {
                    break;
                }
                default:
                {
                }
            }
	    }

	    if (event.eventtype == MinetEvent::Timeout) {
	    // timeout ! probably need to resend some packets
	    }

    }

    }

    MinetDeinit();

    return 0;

}
