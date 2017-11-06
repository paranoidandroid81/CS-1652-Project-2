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
#include "tcpstate.h"
#include "constate.h"
#include "packet.h"
#include "tcpstate.h"

using namespace std;


enum TCPFlags = {ACK, SYN, FIN, RST};

bool conductStateTransition (int current, int next, TCPState * fsm) {
  if (!(fsm->GetState() == current)) return false;
  else fsm->setState(next);
  return true;
}

bool beginTransfer(TCPState * fsm, Packet pkt) {
  // SetSourcePort(&(fsm->srcPort), pkt);
  // SetDestPort(&(fsm->destPort), pkt);
  //Officially enter data transfer state
  //Send ack first!
}

bool concludeHandshake(TCPState * fsm, Packet *pkt) {
  //Send ack! wait for data transfer
  Packet p;
  unsigned short len;
  bool checksumok;
  MinetReceive(fsm->ipMux, p); //TODO fix this!
  p->ExtractHeaderFromPayload(TCPHeader, 8); //Why 8? This might need to change
  TCPHeader tcph;
}

//parses pkt headers and returns a connection
Connection getConnection (Header::TCPHeader * tcpHead, Header::IPHeader ipHead) {
    IPAddress* srcIP, destIP;
    ipHead->GetSourceIP(srcIP);
    ipHead->GetDestIP(destIP);

    unsigned int srcPort, destPort;
    tcpHead->getSrcPort(&srcPort);
    tcpHead->getDestPort(&destPort);

    return Connection(srcIP, destIP, srcPort, destPort, 0); //TODO protocol var is wrong!
}

Packet getPacket (int handle) {
  Packet * pk = calloc(sizeof(Packet));
  if (MinetReceive(&handle, pk) > 0) return pk;
  else return NULL; //throw error here?
}

bool resetHandshake (TCPState * fsm, Packet pkt) {
  //received reset, set handshake back to original state


}

bool sendSynAck (TCPState * fsm, Packet pkt) {
  //Store IP info? Or do this at begin fsm
}

bool transferData(TCPState * fsm, Packet pkt) {

}

bool closeWait (TCPState * fsm, Packet pkt) {

}

bool handleTimeout (TCPState * fsm, Packet pkt) {

}

bool startHandshake (Connection c) {
  Packet p;
  char flags = 0;
  SET_ACK(&flags);
  SET_SYN(&flags);
  TCPHeader tcph = TCPHead();
}

bool passiveOpen (Packet *p, ConnectionList<TCPState> clist) {
  //recvd syn, send syn-ack
  TCPHeader tcph = p->popBackHeader();
  IPHeader iph = p->popFrontHeader();
  Connection newConn = getConnection(tcph, iph);
  clist.push_back(newConn);
  //Send syn-ack
  char flags = 0;
  SET_SYN(&flags);
  SET_ACK(&flags);
  int n;
  tcph.GetSeqNum(&n);
  //Check if pkt is ok!
  TCPHeader resp_tcph;
  resp_tcph.SetSeqNum();

}

Connection getConnection (TCPHeader tchp, IPHeader iph) {
  Connection c;
  iph.GetDestIP(c.src);
  iph.GetSourceIP(c.dest);
  iph.GetProtocol(c.protocol);
  tcph.GetDestPort(c.srcport);
  tcph.GetSourcePort(c.destport);
  return c;
}

Packet makeAck (Packet *pkt, TCPState connstate) {
  TCPHeader tcph = pkt->popBackHeader();
  IPHeader iph = pkt->popFrontHeader();
  bool checksumok = tcph.IsCorrectChecksum(p);

  int acknum;
  TCPHeader resp_tcph = TCPHeader();
  IPHeader resp_iph = IPHeader();
  Packet response;

  if (!checksumok) acknum = connstate.GetLastAcked(); //Ack last packet!
  else {
    int n;
    tcph.GetSeqNum(&n);
    acknum = ( n == 0 ? 1 : 0); //Non pipelined, only need 2 seq. nums
  }


  resp_iph.SetSourceIP(iph.GetDestIP());
  resp_iph.SetDestIP(iph.GetSourceIP());
  resp_iph.SetProtocol(IP_PROTO_TCP);
  resp_iph.SetTotalLength(TCP_HEADER_BASE_LENGTH + IP_HEADER_BASE_LENGTH);
  response.PushFrontHeader(&resp_iph);

  unsigned char flags = 0;
  SET_ACK(&flags);
  resp_tcph.SetFlags(&flags, response);
  resp_tcph.SetSeqNum(&acknum, &response);
  resp_tcph.SetSourcePort(tcph.GetDestPort());
  resp_tcph.SetDestPort(tcph.GetSourcePort());
  resp_tcph.SetLength(TCP_HEADER_BASE_LENGTH, response);
  response.PushBackHeader(&resp_tcph);
  return response; //Does it need a buffer?
}

 bool changeState (Packet *pkt, ConnectionList<TCPState> clist) {
  //Responds to an IP event based on the packet type and current fsm state
  //Get header from packet
  IPHeader ipHead = pkt->PopFrontHeader();
  TCPHeader tcpHead = pkt->PopBackHeader();
  bool checksumok = tcph.IsCorrectChecksum(p);
  ConnectionList<TCPState>::iterator conn = clist.FindMatching(getConnection(tcpHead, ipHead));
  int current;
  if (conn == clist.end()) {
    conn = NULL;
    current = 1;
  }
  else {
    TCPState cState = conn.state;
    current = cState.getState();
  }

  //Connection pktConn = getConnection (tcpHead, ipHead);
  //buffer *payload = pkt->GetPayload(); //TODO change functions to take payload/connection not pkt
  char l;
  tcpHead_>GetHeaderLen(&l);
  unsigned char *flags = malloc(l);
  tcpHead->GetFlags(flags);

  switch (current) {

    case (1) { //LISTEN
      return IS_SYN(flags) ? startHandshake(fsm, pkt) : false;
    }

    case (2) { //SYN_RCVD
      if (IS_ACK(flags)) return beginTransfer(fsm, pkt);
      else if (IS_RST(flags)) return resetHandshake(fsm, pkt);
      else return false;
    }

    case (3) { //SYN_SENT
      if (IS_SYN(flags)) return (IS_ACK(flags) ? concludeHandshake(fsm, pkt) : sendSynAck(fsm, pkt));
      else return false;
    }

    case (4) { //SYN_SENT1
      //TODO
    }
    case (5) { //ESTABLISHED
      return IS_FIN(flags) ? closeWait(fsm, pkt) : transferData(connnection, pkt);
    }
    case (6) { //SEND_DATA
      //TODO
    }
    case (7){ //CLOSE_WAIT
      //TODO close wait
    }

    case (8) { //FIN_WAIT1
     return IS_FIN(flags) ?
       ( IS_ACK(flags) ?
           timeWait(fsm, pkt) :
           initiateClose(fsm, pkt) )
     :
       ( IS_ACK(flags) ?
           finWait2(fsm, pkt) :
           false );
    }

    case (9) { //CLOSING
      //TODO
    }
    case (10) { //LAST_ACK
      //TODO
    }

    case (11) { //FIN_WAIT2
      return IS_FIN(flags) ? timeWait(fsm, pkt) : false;
    }

    case (12) { //TIME_WAIT
      return IS_ACK(flags) ? timeWait(fsm, pkt) : false;
    }

    default { return false; }

    }
  }


bool handleAppRequest(TCPState * fsm, MinetHandle * sock) {
  //TODO: Handle app requests!!! (TCP-Socket layer interface)
  return false;
}


bool listen(TCPState * fsm, MinetHandle * ipmux, MinetHandle * minSock) {
  //Waits to receive syn or be asked to send data, sends syn-ack to client

  State deisred = CLOSED;
  if (!fsm->isInState(CLOSED)) return false;
  else fsm->setStateTo(LISTEN);

}

bool activeOpen(TCPState * fsm) {
  //Actively opens a fsm to a client
  if ( !(fsm->isInState(CLOSED) || fsm->isInState(LISTED)) ) return false;


}

bool passiveOpen (TCPState * fsm, MinetHandle * ipmux, MinetHandle * sock ) {
  //Passively opens a fsm
  listen(fsm, ipmux, );

  conductStateTransition(CLOSED, LISTEN, fsm);
}

bool receiveSyn(TCPState * fsm, MinetHandle * ipmux) {

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

    ConnectionList<TCPState> clist = ConnectionList<TCPState>();

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
            changeState(p, clist);
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
            changeState(cs.state);
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
