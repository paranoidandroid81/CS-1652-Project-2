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
//
//
// bool concludeHandshake(TCPState * fsm, Packet *pkt) {
//   //Send ack! wait for data transfer
//   Packet p;
//   unsigned short len;
//   bool checksumok;
//   MinetReceive(fsm->ipMux, p); //TODO fix this!
//   p->ExtractHeaderFromPayload(TCPHeader, 8); //Why 8? This might need to change
//   TCPHeader tcph;
// }

Connection getConnection (TCPHeader tchp, IPHeader iph) {
  Connection c;
  iph.GetDestIP(c.src);
  iph.GetSourceIP(c.dest);
  iph.GetProtocol(c.protocol);
  tcph.GetDestPort(c.srcport);
  tcph.GetSourcePort(c.destport);
  return c;
}

Packet makeAck (Packet *pkt, int lastacked, bool isSyn) {
  TCPHeader tcph = pkt->popBackHeader();
  IPHeader iph = pkt->popFrontHeader();
  bool checksumok = tcph.IsCorrectChecksum(p);

  int acknum;
  TCPHeader resp_tcph = TCPHeader();
  IPHeader resp_iph = IPHeader();
  Packet response;

  if (!checksumok) {
    if (!isSyn) acknum = lastacked; //Ack last packet!
    else return NULL;
  }
  else {
    int n;
    tcph.GetSeqNum(&n);
    acknum = n; //Non pipelined, only need 2 seq. nums
  }

  resp_iph.SetSourceIP(iph.GetDestIP());
  resp_iph.SetDestIP(iph.GetSourceIP());
  resp_iph.SetProtocol(IP_PROTO_TCP);
  resp_iph.SetTotalLength(TCP_HEADER_BASE_LENGTH + IP_HEADER_BASE_LENGTH);
  response.PushFrontHeader(&resp_iph);

  unsigned char flags = 0;
  SET_ACK(&flags);
  if (isSyn) SET_SYN(&flags);
  resp_tcph.SetFlags(&flags, response);
  resp_tcph.SetSeqNum(&acknum, &response);
  resp_tcph.SetSourcePort(tcph.GetDestPort());
  resp_tcph.SetDestPort(tcph.GetSourcePort());
  resp_tcph.SetLength(TCP_HEADER_BASE_LENGTH, response);
  response.PushBackHeader(&resp_tcph);
  return response; //Does it need a buffer?
}

bool handle_packet (MinetHandle &mux, MinetHandle &sock,
                      ConnectionList<TCPState> clist) {
  Packet p;
  TCPHeader tcph;
  IPHeader iph;

  MinetReceive(mux, p);

  unsigned int tcphLen = TCPHeader::EstimateTCPHeaderLength(p);
  p.ExtractHeaderFromPayLoad(tcphLen);
  tcph = p.FindHeader(Headers::TCPHeader);
  iph = p.FindHeader(Headers::IPHeader);

  bool ischecksumok = tcph.isCorrectChecksum(p);
  if (!ischecksumok) return false;

  unsigned char flags;
  unsigned int ack;
  unsigned int seqnum;
  unsigned short winsize;
  unsigned char tcphsize;
  unsigned char iphsize;
  unsigned short contentsize;

  tcph.GetFlags(flags);
  tcph.GetAckNum(ack);
  tcph.GetSeqNum(seqnum);
  tcph.GetWinSize(winsize);
  tcph.GetHeaderLength(tcphsize);
  iph.GetHeaderLength(iphsize);
  iph.GetTotalLength(contentsize);

  unsigned short payloadsize = contentsize - (tcphsize*4) - (iphsize * 4);

  Buffer payload = p.GetPayload().ExtractFront(payloadsize);


  Connection conn = getConnetion(tcph, iph);
  ConnectionList<TCPState>::iterator conStateMap = clist.FindMatching(conn);
  unsigned int currentState;
  if (conStateMap == clist.end()) {
    //pass
  }

  currentState = conStateMap->state.GetState();
  Packet response;
  unsigned char rflags = 0;


  switch (current) {

    case (1): //LISTEN
    cerr << "\nLISTEN\n";
      if (IS_SYN(flags)) {
        //Update connection-state mapping with iterator
        conStateMap->connection = conn;
        conStateMap->state.SetState(SYN_RCVD);
        conStateMap->state.last_acked = conStateMap->state.last_sent;
        conStateMap->state.SetLastRecvd(seqnum + 1);
        conStateMap->bTmrActive = true;
        conStateMap->timeout=Time() + 8;
        conStateMap->state.last_sent++;

        //Send syn-ack
        SET_ACK(rflags);
        SET_SYN(rflags)
        make_packet(response, *(conStateMap), rflags, 0, false);
        MinetSend(mux, response);
      }
      break;

    case (2): //SYN_RCVD
    cerr << "\nSYN_RCVD\n";

      if (IS_ACK(flags)) {
        conStateMap->state.setState(ESTABLISHED);
        conStateMap->state.SetLastAcked(ack);
        conStateMap->state.SetSendRwnd(winsize);
        conStateMap->state.last_sent++;
        conStateMap->bTmrActive = false;

        static SockRequestResponse * write = NULL;
        write = new SockRequestResponse(WRITE, conStateMap->connection, payload, 0, EOK);
        MinetSend(sock, *write);
        delete write;
      }
      else if (IS_RST(flags)) {
        //TODO
      };
      else return false;
      break;

    case (3):  //SYN_SENT
    cerr << "\nSYN_SENT\n";

      if (IS_SYN(flags)) {
        if (IS_ACK(flags)) {
          conStateMap->state.SetSendRwnd(winsize);
          conStateMap->state.SetLastRecvd(seqnum + 1);
          conStateMap->state.last_acked = ack;

          conStateMap->state.last_sent++;
          SET_ACK(rflags);
          make_packet(response, *conStateMap, rflags, 0, false);
          MinetSend(mux, response);
          conStateMap->state.SetState(ESTABLISHED);
          conStateMap->bTmrActive = false;

          SockRequestResponse write (WRITE, conStateMap->connection, payload, 0, EOK);
          MinetSend(sock, write);
        }
      }

      break;

    case (4):  //SYN_SENT1
      //TODO
      break;

    case (5):  //ESTABLISHED
    cerr << "\nESTABLISHED\n";

      if (IS_FIN(flags)) {
        conStateMap->state.SetState(CLOSE_WAIT);
        conStatemap->state.SetLastRecvd(seqnum + 1);

        conStateMap->bTmrActive = true;
        conStateMap->timeout = Time() + 8;
        SET_ACK(rflags)
        make_packet(response, *conStateMap, rflags, 0, false);
        MinetSend(mux, response);

        Packet lastack;
        conStateMap->state.SetState(LAST_ACK);
        rflags = 0;
        SET_FIN(rflags);
        make_packet(p, *conStateMap, rflags, 0, false);
      }
      if (contentsize != 0) {
        conStateMap->state.SetSendRwnd(winsize);
        conStateMap->state.last_recvd = seqnum + payload.GetSize();
        conStateMap->state.RecvBuffer.AddBack(payload);
        SockRequestResponse write (WRITE, conStateMap->connection, conStateMap->RecvBuffer,
                                    ConStateMap->RecvBuffer.GetSize(), EOK);
        MinetSend(sock, write);
        conStateMap->RecvBuffer.Clear();
        rflags = 0;
        SET_ACK(rflags);
        make_packet(response, *conStateMap, rflags, 0, false);
        MinetSend(mux, response);
      }
      if (IS_ACK(flags)) {

        if (ack >= conStateMap->state.last_acked) {
          int amt_ackd = ack - conStateMap->state.last_acked;
          conStateMap->state.last_acked = ack;
          conStateMap->state.SendBuffer.Erase(0, amount_of_data_acked);
          conStateMap->bTmrActive = false;

        }
        if (conStateMap->state.GetState() == LAST_ACK) {
          conStateMap->state.SetState(CLOSED);
          clist.erase(conStateMap);
        }
      }
      break;

    case (6):  //SEND_DATA
      if (IS_ACK(flags)) {
        unsigned int bytesAcked;
        if (ack < conStateMap->last_acked) return false; //Bolean check because both are unsigned
        else bytesAcked = ack - conStateMap.last_acked;
        conStateMap->state.last_acked = ack;
        conStateMap->state.SendBuffer.Erase(0, bytesAcked);
        conStateMap->bTmrActive = false;
        if (conStateMap->state.SendBuffer.GetSize() <= 0) {
          //Send socket response that transfer was ok
          conStateMap->state.SetState(ESTABLISHED);
          return true;
        }
        Buffer nextPayload = conStateMap->state.SendBuffer.ExtractFront(bytesAcked);
        stopWaitSend(mux, *conStateMap, nextPayload);
      }
      break;

    case (7): //CLOSE_WAIT
      //TODO close wait
      break;

    case (8) : //FIN_WAIT1
    cerr << "\nFINWAIT1\n";

     if (IS_ACK(flags)) conStateMap->state.SetState(FIN_WAIT2);
     if (IS_FIN(flags)) {
       conStateMap->state.SetState(TIME_WAIT);
       conStateMap->state.SetLastRecvd(seqnum+1);
       SET_ACK(rflags);
       make_packet(response, *conStateMap, rflags, 0, false);

       conStateMap->bTmrActive = true;
       conStateMap->timeout = Time() + (2*MSL_TIME_SECS);
       MinetSend(mux, response);
     }
     break;

    case (9) : //CLOSING
      //TODO
      break;

    case (10) : //LAST_ACK
    cerr << "\nLASTACK\n";

      if (IS_ACK(flags)) {
        conStateMap->state.SetState(CLOSED);
        clist.erase(conStateMap);
      }
      break;

    case (11) : //FIN_WAIT2
    cerr << "\nFINWAIT2\n";

      if (IS_FIN(flags)) {
        conStateMap->state.SetState(TIME_WAIT);
        conStateMap->state.SetLastRecvd(seqnum + 1);
        SET_ACK(rflags);
        make_packet(response, *conStateMap, rflags, 0, false);

        conStateMap->bTmrActive = true;
        conStateMap->timeout = Time() + (2*MSL_TIME_SECS);
        MinetSend(mux, response);

      }
      break;

    case (12) : //TIME_WAIT
    cerr << "\nTIMEWAIT\n";

      if (IS_FIN(flags)) {
        conStateMap->state.SetLastRecvd(seqnum+1);
        conStateMap->timeout = Time() + (2*MSL_TIME_SECS);
        SET_ACK(rflags);
        make_packet(response, *conStateMap, rflags, 0, false);
        MinetSend(mux, response);
      }
      break;

   cerr << "\nHandle packet complete: New State is " << conStateMap->state.GetState() << endl;


    }
  }
}

 int stopWaitSend (const MinetHandle &mux, ConnectionToStateMapping<TCPState> &tcp_csm,
                  Buffer data) {
      Packet pkt;
      tcp_csm.state.SendBuffer.AddBack(data); //Move to sock layer!!!
      unsigned int dataSize = min(data.GetSize(), TCP_MAXIMUM_SEGMENT_SIZE);
      // char databuff[sendBytes + 1];
      // int dataSize = data.GetData(databuff, sendBytes, 0); //Is this ok? should i be using sendbuff
      // Buffer sendBuff;
      // sendBuff.SetData(databuff, dataSize, 0);
      pkt(data.ExtractFront(dataSize));
      cerr << "Sending data at offest " << end << " of size " << dataSize << "\n";
      make_packet(p, tcp_csm, 0, dataSize);
      MinetSend(mux, p);
      tcp_csm.state.last_sent += dataSize;
      return sendBytes; //return num bytes sent
 }


bool handleAppRequest(TCPState * fsm, MinetHandle * sock) {
  //TODO: Handle app requests!!! (TCP-Socket layer interface)
  return false;
}


bool listen(TCPState * fsm, MinetHandle * ipmux, MinetHandle * minSock) {
  //Waits to receive syn or be asked to send data, sends syn-ack to client

  if (!fsm->isInState(CLOSED)) return false;
  else fsm->setStateTo(LISTEN);

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
            handlePacket(mux, sock, clist);
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
