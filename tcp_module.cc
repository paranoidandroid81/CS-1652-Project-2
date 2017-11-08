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

Connection getConnection (TCPHeader tchp, IPHeader iph) {
  Connection c;
  iph.GetDestIP(c.src);
  iph.GetSourceIP(c.dest);
  iph.GetProtocol(c.protocol);
  tcph.GetDestPort(c.srcport);
  tcph.GetSourcePort(c.destport);
  return c;
}

// Packet makeAck (Packet *pkt, int lastacked, bool isSyn) {
//   TCPHeader tcph = pkt->popBackHeader();
//   IPHeader iph = pkt->popFrontHeader();
//   bool checksumok = tcph.IsCorrectChecksum(p);
//
//   int acknum;
//   TCPHeader resp_tcph = TCPHeader();
//   IPHeader resp_iph = IPHeader();
//   Packet response;
//
//   if (!checksumok) {
//     if (!isSyn) acknum = lastacked; //Ack last packet!
//     else return NULL;
//   }
//   else {
//     int n;
//     tcph.GetSeqNum(&n);
//     acknum = n; //Non pipelined, only need 2 seq. nums
//   }
//
//   resp_iph.SetSourceIP(iph.GetDestIP());
//   resp_iph.SetDestIP(iph.GetSourceIP());
//   resp_iph.SetProtocol(IP_PROTO_TCP);
//   resp_iph.SetTotalLength(TCP_HEADER_BASE_LENGTH + IP_HEADER_BASE_LENGTH);
//   response.PushFrontHeader(&resp_iph);
//
//   unsigned char flags = 0;
//   SET_ACK(&flags);
//   if (isSyn) SET_SYN(&flags);
//   resp_tcph.SetFlags(&flags, response);
//   resp_tcph.SetSeqNum(&acknum, &response);
//   resp_tcph.SetSourcePort(tcph.GetDestPort());
//   resp_tcph.SetDestPort(tcph.GetSourcePort());
//   resp_tcph.SetLength(TCP_HEADER_BASE_LENGTH, response);
//   response.PushBackHeader(&resp_tcph);
//   return response; //Does it need a buffer?
// }

bool handle_packet (MinetHandle &mux, MinetHandle &sock,
                      ConnectionList<TCPState> clist) {
  Packet p;
  TCPHeader tcph;
  IPHeader iph;
  Buffer payLoad;
  unsigned int currentState;

  MinetReceive(mux, p);
  tcph = p.PopBackHeader(Headers::TCPHeader);
  if (!tcph.isCorrectChecksum(p)) return false;
  iph = p.PopFrontHeader(Headers::IPHeader);
  payload = p.GetPayload();
  Connection conn = getConnetion(tcph, iph);
  ConnectionList<TCPState>::iterator conStateMap = clist.FindMatching(conn);

  unsigned char flags;
  unsigned int ack;
  unsigned int seqnum;
  unsigned short winsize;
  unsigned char tcphsize;
  unsigned char iphsize;
  unsigned short totalsize;

  tcph.GetFlags(flags);
  tcph.GetAckNum(ack);
  tcph.GetSeqNum(seqnum);
  tcph.GetWinSize(winsize);
  tcph.GetHeaderLength(tcphsize);
  iph.GetHeaderLength(iphsize);
  iph.GetTotalLength(totalsize);


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
        conStateMap->state.SetLastRecvd(seqnum + 1);
        conStateMap->state.last_acked = conStateMap->state.last_sent;

        //Send syn-ack
        SET_ACK(rflags);
        SET_SYN(rflags);
        makePacket(response, *(conStateMap), rflags, 0, false);
        MinetSend(mux, response);
        conStateMap->state.last_sent++;
        conStateMap->bTmrActive = true;
        conStateMap->timeout=Time() + 8;

      }
      break;

    case (2): //SYN_RCVD
    cerr << "\nSYN_RCVD\n";

      if (IS_ACK(flags)) {

        conStateMap->state.SetState(ESTABLISHED);
        conStateMap->state.SetLastAcked(ack);
        conStateMap->state.SetSendRwnd(winsize);
        conStateMap->bTmrActive = false;
        //conStateMap->state.last_sent++; take out if unneeded

        static SockRequestResponse * write = NULL;
        write = new SockRequestResponse(WRITE, conStateMap->connection, payload, 0, EOK);
        MinetSend(sock, *write);
        //delete write;
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
          conStateMap->bTmrActive = false;
          conStateMap->state.SetLastRecvd(seqnum + 1);
          conStateMap->state.last_acked = ack;
          conStateMap->state.SetSendRwnd(winsize);

          //Send final ack to complete handshake
          SET_ACK(rflags);
          makePacket(response, *conStateMap, rflags, 0, false);
          MinetSend(mux, response);
          conStateMap->state.last_sent++;
          conStateMap->state.SetState(ESTABLISHED);

          SockRequestResponse write (WRITE, conStateMap->connection, payload, 0, EOK);
          MinetSend(sock, write);
        }
        else {
          //Invalid State!!!
          cerr << "Invalid state!\n";
          return false;
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

        SET_ACK(rflags)
        makePacket(response, *conStateMap, rflags, 0, false);
        MinetSend(mux, response);
        conStateMap->bTmrActive = true;
        conStateMap->timeout = Time() + 8;

        Packet lastack;
        conStateMap->state.SetState(LAST_ACK);
        rflags = 0;
        SET_FIN(rflags);
        makePacket(p, *conStateMap, rflags, 0, false);
      }
      else if (totalsize != 0) {
        conStateMap->state.SetSendRwnd(winsize);
        conStateMap->state.last_recvd = seqnum + payload.GetSize();
        conStateMap->state.RecvBuffer.AddBack(payload);
        SockRequestResponse write (WRITE, conStateMap->connection, conStateMap->RecvBuffer,
                                    ConStateMap->RecvBuffer.GetSize(), EOK);
        MinetSend(sock, write);
        conStateMap->RecvBuffer.Clear();
        rflags = 0;
        SET_ACK(rflags);
        makePacket(response, *conStateMap, rflags, 0, false);
        MinetSend(mux, response);
      }
      if (IS_ACK(flags)) {

        if (ack >= conStateMap->state.last_acked) {
          int bytesAcked = ack - conStateMap->state.last_acked;
          conStateMap->state.last_acked = ack;
          conStateMap->state.SendBuffer.Erase(0, bytesAcked);
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
        if (ack < conStateMap->last_acked) return false;
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
        int bytesSent = stopWaitSend(mux, *conStateMap, nextPayload);
        conStateMap->bTmrActive = true;
        conStateMap->timeout = Time() + 8; //Why 8?
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
       makePacket(response, *conStateMap, rflags, 0, false);

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
      else {
        cerr << "Invalid state!";
        return false;
      }
      break;

    case (11) : //FIN_WAIT2
    cerr << "\nFINWAIT2\n";

      if (IS_FIN(flags)) {
        conStateMap->state.SetState(TIME_WAIT);
        conStateMap->state.SetLastRecvd(seqnum + 1);
        SET_ACK(rflags);
        makePacket(response, *conStateMap, rflags, 0);

        conStateMap->bTmrActive = true;
        conStateMap->timeout = Time() + (2*MSL_TIME_SECS);
        MinetSend(mux, response);

      }
      else {
        cerr << "invalid state !";
        return false;
      }
      break;

    case (12) : //TIME_WAIT
    cerr << "\nTIMEWAIT\n";

      if (IS_FIN(flags)) {
        conStateMap->state.SetLastRecvd(seqnum+1);
        conStateMap->timeout = Time() + (2*MSL_TIME_SECS);
        SET_ACK(rflags);
        makePacket(response, *conStateMap, rflags, 0);
        MinetSend(mux, response);
      }
      break;

   cerr << "\nHandle packet complete: New State is " << conStateMap->state.GetState() << endl;


    }
}

int stopWaitSend (const MinetHandle &mux, ConnectionToStateMapping<TCPState> &tcp_csm,
                  Buffer data) {
      Packet pkt;
      unsigned int dataSize = min(data.GetSize(), TCP_MAXIMUM_SEGMENT_SIZE);
      // char databuff[sendBytes + 1];
      // int dataSize = data.GetData(databuff, sendBytes, 0); //Is this ok? should i be using sendbuff
      // Buffer sendBuff;
      // sendBuff.SetData(databuff, dataSize, 0);
      pkt(data.ExtractFront(dataSize));
      cerr << "Sending data at offest " << end << " of size " << dataSize << "\n";
      make_packet(p, tcp_csm, 0, dataSize);
      MinetSend(mux, p);
      tcp_csm->state.bTmrActive = true;
      tcp_csm->state.timeout = Time() + 8;
      tcp_csm.state.last_sent += dataSize;
      return sendBytes; //return num bytes sent
 }

void makePacket(Packet &p, ConnectionToStateMapping<TCPState> &curr, unsigned char flags,
                    int size, bool timeout) {
        cerr << "\nMaking packet...\n";
        int packet_size = size + TCP_HEADER_BASE_LENGTH + IP_HEADER_BASE_LENGTH;
        IPHeader iph;
        TCPHeader tph;
        iph.SetProtocol(IP_PROTO_TCP);
        iph.SetSourceIP(curr.connection.src);
        iph.SetDestIP(curr.connection.dest);
        iph.SetTotalLength(packet_size);
        p.PushFrontHeader(iph);
        cerr << "\nIP Header: \n" << iph << endl;
        tph.SetSourcePort(curr.connection.srcport, p);
        tph.SetDestPort(curr.connection.destport, p);
        //length of TCP header in words = 5
        tph.SetHeaderLength(5, p);
        tph.SetAckNum(curr.state.GetLastRecvd(), p);
        tph.SetWinSize(curr.state.GetN(), p);
        tph.SetUrgentPtr(0, p);
        tph.SetFlags(flags, p);
        cerr << "\nLast Ack: \n" << curr.state.GetLastAcked() << endl;
        cerr << "\nSeq + 1: \n" << curr.state.GetLastSent() + 1 << endl;
        //If this is a timeout, seq num is last seq num that other party
        //ACK'd, otherwise it is last sent + 1
        if (timeout) {
            tph.SetSeqNum(curr.state.GetLastAcked(), p);
        } else {
            tph.SetSeqNum(curr.state.GetLastSent() + 1, p);
        }
        tph.RecomputeChecksum(p);
        cerr << "\nTCP Header: \n" << tph << endl;
        p.PushBackHeader(tph);
        cerr << "\nDone making packet...\n";
}

void handleSock(MinetHandle &mux, MinetHandle &sock. ConnectionList<TCPState> &clist) {
    cerr << "\nHandling socket...\n";
    SockRequestResponse req;
    SockRequestResponse repl;
    //get conn info from socket
    MinetReceive(sock, req);
    Packet p;
    unsigned char flags;
    ConnectionList<TCPState>::iterator cs;
    cs = clist.FindMatching(req.connection);
    if (cs == clist.end()) {
        //no conn found, need to create new
        cerr << "\nNo connection found in the list. Creating new...\n";
        switch (req.type) {
            //active open to remote, send SYN
            case CONNECT: {
                cerr << "\nConnect type...\n";
                TCPState state(1, SYN_SENT, 5);       //TODO: why timertries =5 and why ISN = 1
                SET_SYN(flags);
                ConnectionToStateMapping<TCPState> ctsmap(req.connection, Time() + 2,
                                                        state, true);
                ctsmap.state.last_acked = 0;
                clist.push_back(ctsmap);
                makePacket(p, ctsmap, flags, 0, false);        //size 0 as SYN w/o data
                //sets timer active, sets timeout
                cs->bTmrActive = true;
                cs->timeout = Time() + 2;
                MinetSend(mux, p);
                //inform socket SYN has been sent
                repl.type = STATUS;
                repl.connection = req.connection;
                repl.bytes = 0;
                repl.error = EOK;
                MinetSend(sock, rep);
                cerr << "\nConnection created!\n";
                cerr << ctsmap.connection << endl;
                cerr << "Current state: " << ctsmap.state.GetState() << endl;
                cerr << "\nConnect finished...\n";
                break;
            }
            //passive open from remote, send nothing
            case ACCEPT: {
                cerr << "\nAccept type...\n";
                TCPState state(1, LISTEN, 5);
                ConnectionToStateMapping<TCPState> ctsmap(req.connection, Time(),
                                                            state, false);
                clist.push_back(ctsmap);
                //inform socket passive conn setup
                repl.type = STATUS;
                repl.bytes = 0;
                repl.connection = req.connection;
                repl.error = EOK;
                MinetSend(sock, repl);
                cerr << "\nConnection created!\n";
                cerr << ctsmap.connection << endl;
                cerr << "Current state: " << ctsmap.state.GetState() << endl;
                cerr << "\nAccept finished...\n";
                break;
            }
            //ignore
            case STATUS: {
                break;
            }
            //impossible to write to nonexistent conn, send error to sock
            case WRITE: {
                repl.type = STATUS;
                repl.connection = req.connection;
                repl.bytes = 0;
                repl.error = ENOMATCH;
                MinetSend(sock, repl);
                break;
            }
            //ignore
            case FORWARD: {
                break;
            }
            //impossible to close nonexistent conn
            case CLOSE: {
                repl.type = STATUS;
                repl.connection = req.connection;
                repl.bytes = 0;
                repl.error = ENOMATCH;
                MinetSend(sock, repl);
                break;
            }
            default: {
                break;
            }
        }
    }
    else {
        cerr << "\nConnection found in the list...\n";
        unsigned int currState;
        currState = cs->state.GetState();
        switch (req.type) {
            //already extant, can't do new active open
            case CONNECT: {
                break;
            }
            case ACCEPT: {
                break;
            }
            //data to send
            case WRITE: {
                cerr << "\nSock write request...\n";
                if (state == ESTABLISHED) {
                    //check if room in send buffer
                    if ((cs->state.SendBuffer.GetSize() + req.data.GetSize())
                        > (cs->state.TCP_BUFFER_SIZE)) {
                            //buffer overflow
                            repl.type = STATUS;
                            repl.connection = req.connection;
                            repl.bytes = 0;
                            repl.error = EBUF_SPACE;
                            MinetSend(sock, repl);
                        } else if (cs->state.SendBuffer.GetSize() <= 0) {
                          //TODO: Send buffer has data!
                          return false;
                        } else {
                            Buffer buf = req.data;
                            //set timer for write
                            cs->bTmrActive = true;
                            cs->timeout = Time() + 8;

                            //Add data to send buffer and send it!
                            cs->state->SendBuffer.AddBack(buf);
                            int ret = stopWaitSend(mux, *cs, buf);
                            cerr << "\nSending this data...\n";
                            cerr << buf << endl;
                            //if success, inform socket
                            if (ret != 0) {
                                repl.type = STATUS;
                                repl.connection = req.connection;
                                repl.byte = buf.GetSize();
                                repl.error = EOK;
                                MinetSend(sock, repl);
                                cs->state.SetState(SEND_DATA);
                            }
                            else {
                              //Err, no bytes sent!
                              cerr < "No bytes sent!"
                              return false;
                            }
                        }
                }
                cerr << "\nWrite finished...\n";
                break;
            }
            //ignore
            case FORWARD: {
                break;
            }
            //need to close connection
            case CLOSE: {
                cerr << "\nSock close request...\n";
                if (state == ESTABLISHED) {
                    //send FIN
                    cs->state.SetState(FIN_WAIT1);
                    cs->state.last_acked = cs->state.last_acked + 1;
                    //begin timeout period for FIN
                    cs->bTmrActive = true;
                    cs->timeout = Time() + 8;
                    SET_FIN(flags);
                    makePacket(p, *cs, flags, 0, false);
                    MinetSend(mux, p);
                    //inform conn we sent FIN
                    repl.type = STATUS;
                    repl.connection = req.connection;
                    repl.bytes = 0;
                    repl.eroor = EOK;
                    MinetSend(sock. repl);
                }
                cerr << "\nClose finished...\n";
                break;
            }
            //handled in write so ignore
            case STATUS: {
                break;
            }
            default: {
                break;
            }
        }
    }
    cerr << "\nEnd of socket handling...\n";
}

void handleTimeout(MinetHandle &mux, ConnectionList<TCPState>::iterator it,
                    ConnectionList<TCPState> &clist) {
    cerr << "\nTime out happened on conn in list!\n";
    unsigned int state = it->state.GetState();
    Packet p;
    unsigned char flags;
    Buffer buf;
    unsigned short len;
    switch (state) {
        //resend SYN packet
        case SYN_SENT: {
            SET_SYN(flags);
            //timeout false because no ACK has so SYN seq is just ISN
            makePacket(p, *it, flags, 0, false);
            MinetSend(mux, p);
            break
        }
        //resend SYNACK
        case SYN_RCVD: {
            SET_SYN(flags);
            SET_ACK(flags);
            makePacket(p, *it, flags, 0, true);
            MinetSend(mux, p);
            break;
        }
        //resend sent data
        case ESTABLISHED: {
            //find data lost in timeout, extract it from send buffer
            len = (it->state.last_sent) - (it->state.last_acked);
            buf = it->state.SendBuffer;
            buf = buf.ExtractFront(len);
            sendData(mux, *it, data, true);
            break;
        }
        //resend FIN after initial FIN
        case FIN_WAIT1:
        //resend FIN afer FIN in response
        case LAST_ACK: {
            SET_FIN(flags);
            makePacket(p, *it, flags, 0)
            MinetSend(mux, p);
            break;
        }
        //assume they got ACK and close
        case TIME_WAIT: {
            cerr << "\nTime wait expired...\n";
            it->state.SetState(CLOSED);
            clist.erase(it);
        }
        default:
            break;
    }
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

    cerr << "tcp_module stop and wait handling tcp traffic.......\n";

    MinetSendToMonitor(MinetMonitoringEvent("tcp_module stop and waithandling tcp traffic........"));

    MinetEvent event;
    double timeout = 1;

    while (MinetGetNextEvent(event, timeout) == 0) {

	     if ((event.eventtype == MinetEvent::Dataflow) &&
	         (event.direction == MinetEvent::IN)) {

             cerr << "\nMinet event arriving...\n";
             if (event.handle == mux) {
                 cerr << "\nTCP mux packet has arrived!\n";
    		     // ip packet has arrived!
                 handle_packet(mux, sock, clist);
             }

    	     if (event.handle == sock) {
        		 // socket request or response has arrived
                 cerr << "\nTCP sock req or resp arrived!\n";
                 handle_sock(mux, sock, clist);
    	     }
         }

    	 if (event.eventtype == MinetEvent::Timeout) {
    	     // timeout ! probably need to resend some packets
             //find earliest conn
             ConnectionList<TCPState>::iterator cs = clist.FindEarliest();

             if (cs != clist.end()) {
                 if (Time().operator > ((*cs).timeout)) {
                      handle_timout(mux, cs, clist);
                 }
             }

    	 }

    }



    MinetDeinit();

    return 0;

}
