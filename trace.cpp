/*
Program pro zjištování jednotlivých směrovačů na cestě paketu k cíli.
Autor: Tom Barbořík <xbarbo06>

trace [-f first_ttl] [-m max_ttl] <ip-address>
    -f nastaví první ttl (default 1)
    -m nastaví maximální počet ttl (default 30)
    <ip-address> adresa koncového zařízení (může být jak IPv4, IPv6 tak i doménová adresa)
*/

#include <iostream>
#include <iomanip>
#include <string.h>
#include <sys/time.h>
#include <inttypes.h>
#include <exception>

#include <linux/errqueue.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>

#define BUFFER_SIZE 4096
#define DOMAIN_SIZE 1024

using namespace std;

// controls is str is a numer
bool isNumber(const char *str) {
    bool r = true;
    for (int i = 0; str[i] != 0; i++) {
        r = r && isdigit(str[i]);
    }

    return r;
}

// calculates time difference
int timeval_subtract(struct timeval *result, struct timeval *t2, struct timeval *t1) {
    long int diff = (t2->tv_usec + 1000000 * t2->tv_sec) - (t1->tv_usec + 1000000 * t1->tv_sec);
    result->tv_sec = diff / 1000000;
    result->tv_usec = diff % 1000000;

    return (diff < 0);
}

// converts addrinfo to string
string addrToStr(addrinfo ai) {
    char addrstr[100];

    switch (ai.ai_family) {
        case AF_INET:
            getnameinfo(ai.ai_addr, sizeof(sockaddr_in), addrstr, 100, NULL, 0, NI_NUMERICHOST);
            break;
        case AF_INET6:
            getnameinfo(ai.ai_addr, sizeof(sockaddr_in6), addrstr, 100, NULL, 0, NI_NUMERICHOST);
            break;
    }

    return string(addrstr);
}

// converts sockaddr_storage to string
string sockStrToStr(sockaddr_storage *soge) {

    char addrstr[100];

    switch (soge->ss_family) {
        case AF_INET:
            getnameinfo((sockaddr *) soge, sizeof(sockaddr_in), addrstr, 100, NULL, 0, NI_NUMERICHOST);
            break;
        case AF_INET6:
            getnameinfo((sockaddr *) soge, sizeof(sockaddr_in6), addrstr, 100, NULL, 0, NI_NUMERICHOST);
            break;
    }


    return string(addrstr);
}

// returns domain name for ip stored in soge
string getDomain(sockaddr_storage *soge) {
    char domain[DOMAIN_SIZE] = {0};
    switch (soge->ss_family) {
        case AF_INET6: {
            getnameinfo((sockaddr *) soge, sizeof(sockaddr_in6), domain, DOMAIN_SIZE, NULL, 0, 0);
            break;
        }

        default: {
            getnameinfo((sockaddr *) soge, sizeof(sockaddr_in), domain, DOMAIN_SIZE, NULL, 0, 0);
            break;
        }
    }

    return string(domain);
}

// TRACE EXCEPTION class -> taking care of all exceptions with tracing (so the user knows about them)
class TraceException {
    public:
        TraceException(int, string);
        int getCode();
        string getMessage();
    
    private:
        int code;
        string message;
};

TraceException::TraceException(int i_code, string s_message) {
    code = i_code;
    message = s_message;
}

int TraceException::getCode() {
    return code;
}

string TraceException::getMessage() {
    return message;
}

// TRACE class -> taking care of all tracing
class Trace {
public:
    Trace(string dest) : Trace(dest, 1, 30) { };
    Trace(string, int, int);
    ~Trace();
    void run();

private:
    struct addrinfo dest;
    string s_dest;
    int ttl; // in hops
    int max_ttl; // in hops
    int timeout; // miliseconds
    int dest_socket; // socket descriptor
    int port;

    void createAddr(string);
    void init();
    void setSocket();
    bool setTTL();
    bool handleIPv4Err(struct timeval, struct sock_extended_err *);
    bool handleIPv6Err(struct timeval, struct sock_extended_err *);
};

// constructor
Trace::Trace(string str_dest, int i_ttl, int i_max_ttl) {
    s_dest = str_dest;
    port = 33434;
    ttl = i_ttl;
    max_ttl = i_max_ttl;
    dest_socket = 0;

    if (max_ttl < 1 || max_ttl > 255 || ttl < 1 || ttl > 255) {
        throw TraceException(-21, "Ttl must be between 1 and 255 (both included)");
    }

    if (ttl > max_ttl) {
       throw TraceException(-20, "Max ttl must be higher or equal to ttl");
    }

    init();
}

// destructor
Trace::~Trace() {
    if (dest_socket > 0)
        if (close(dest_socket) < 0)
            throw TraceException(-14, "Error closing socket (" + to_string(errno) + ")");
}

// creates address either from ip or domain name
void Trace::createAddr(string s_addr) {
    struct addrinfo hints, *res;
    bzero((char *) &dest, sizeof(dest));
    memset(&hints, 0, sizeof(hints));

    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    string s_port = std::to_string(port);
    int error = 0;
    if ((error = getaddrinfo(s_addr.c_str(), s_port.c_str(), &hints, &res) != 0)) {
        throw TraceException(-1, "Error getting address for " + s_dest + " (" + to_string(error) + ")");
    }

    dest = res[0];
}

// initializes the class
void Trace::init() {
    createAddr(s_dest);
    timeout = 2000;
    setSocket();
}

// sets socket and its options
void Trace::setSocket() {
    dest_socket = socket(dest.ai_family, dest.ai_socktype, dest.ai_protocol);
    if (dest_socket <= 0) {        
        throw TraceException(-2, "Error creating socket (" + to_string(dest_socket) + ")");
    }

    int on = 1;
    int r = 0;
    if (dest.ai_family == AF_INET) {
        r = setsockopt(dest_socket, SOL_IP, IP_RECVERR, (char *) &on, sizeof(on));
    }
    else {
        r = setsockopt(dest_socket, SOL_IPV6, IPV6_RECVERR, (char *) &on, sizeof(on));
    }

    if (r < 0) {
        throw TraceException(-3, "Error setting the socket (" + to_string(r) + ")");
    }

    if (connect(dest_socket, dest.ai_addr, dest.ai_addrlen) < 0)
        throw TraceException(-2, "Error connection the socket (" + to_string(errno) + ")");  
}

// sets ttl and sets next
// returns false if max ttl was reached otherwise true
bool Trace::setTTL() {
    if (ttl <= max_ttl) {
        int r = 0;
        if (dest.ai_family == AF_INET) {
            r = setsockopt(dest_socket, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
        } else {
            r = setsockopt(dest_socket, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof(ttl));
        }

        if (r < 0) {
            throw TraceException(-10, "Error setting TTL (" + to_string(r) + ")");
        }

        ttl++;

        return true;
    }

    return false;
}

// traces path to the destination
void Trace::run() {
    struct timeval tv, beginTv, endTv, diffTv;
    fd_set rfds;
    int select_res;
    bool reach = false;


    char buffer[BUFFER_SIZE] = {0};
    struct sockaddr_storage target;
    struct iovec *iov;
    struct msghdr *msg;
    struct cmsghdr *cmsg; 

    while (!reach) {
        if (!setTTL()) { // dosáhli sme max. ttl -> konec
            break;
        }

        if (send(dest_socket, NULL, 0, 0) < 0) {
            throw TraceException(-11, "Error sending the socket (" + to_string(errno) + ")");
        }
        gettimeofday(&beginTv, NULL);

        tv.tv_sec = timeout / 1000;
        tv.tv_usec = 0;
        FD_ZERO(&rfds);
        FD_SET(dest_socket, &rfds);

        if ((select_res = select(dest_socket + 1, &rfds, NULL, NULL, &tv)) < 0) { // chyba selectu
            throw TraceException(-12, "Error waiting for the socket (" + to_string(select_res) + ")");
        } else if (select_res == 0) { // timeout
            cout << setw(2) << right << ttl - 1 << "   *" << endl;
        } else { // získali jsme data
        
            gettimeofday(&endTv, NULL); // čas příchodu

            // vytvořím místo pro zprávu / io data / buffer a vynuluji
            msg = (msghdr *) malloc(sizeof(struct msghdr));
            iov = (iovec *) malloc(sizeof(struct iovec));
            memset(buffer, 0, BUFFER_SIZE);
            memset(msg, 0, sizeof(struct msghdr));
            memset(iov, 0, sizeof(struct iovec));
            msg->msg_name = &target; 
            msg->msg_namelen = sizeof(target); 
            msg->msg_iov = iov; 
            msg->msg_iovlen = 1;
            msg->msg_flags = 0;
            msg->msg_control = buffer;
            msg->msg_controllen = BUFFER_SIZE;

            if (recvmsg(dest_socket, msg, MSG_ERRQUEUE) < 0) {                
                throw TraceException(-13, "Error reading the socket (" + to_string(errno) + ")");
            }

            cout << setw(2) << right << ttl - 1 << "   ";
            timeval_subtract(&diffTv, &endTv, &beginTv); // doba cesty
            
            for (cmsg = CMSG_FIRSTHDR(msg); cmsg != NULL; cmsg = CMSG_NXTHDR(msg, cmsg)) {

                if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_RECVERR) {
                    struct sock_extended_err *sock_err = (struct sock_extended_err *) CMSG_DATA(cmsg);;

                    // obtained the right error -> can proceed
                    if (sock_err && sock_err->ee_origin == SO_EE_ORIGIN_ICMP) {
                        struct sockaddr_in *skin = (struct sockaddr_in *) SO_EE_OFFENDER(sock_err); // getting sender address
                        string domain = getDomain((sockaddr_storage *) skin); // setting sender domain name (if exists -> else we get the ip)


                        //printing base informations
                        string addrstr = sockStrToStr((sockaddr_storage *) skin); // address string
                        if (domain == "") domain = addrstr;
                        cout << domain;
                        cout << " (" << addrstr << ")";

                        reach = handleIPv4Err(diffTv, sock_err);
                    }

                } else if (cmsg->cmsg_level == SOL_IPV6 && cmsg->cmsg_type == IPV6_RECVERR) {
                    struct sock_extended_err *sock_err = (struct sock_extended_err *) CMSG_DATA(cmsg);;

                    if (sock_err && sock_err->ee_origin == SO_EE_ORIGIN_ICMP6) { // recieved the right error
                        struct sockaddr_in6 *skin6 = (struct sockaddr_in6 *) SO_EE_OFFENDER(sock_err); // getting address
                        string domain = getDomain((sockaddr_storage *) skin6); // gettin domain

                        string addrstr = sockStrToStr((sockaddr_storage *) skin6); // address string
                        if (domain == "") domain = addrstr;
                        cout << domain;
                        cout << " (" << addrstr << ")";

                        reach = handleIPv6Err(diffTv, sock_err);
                    }
                }
            }
            free(msg);
            free(iov);

            cout << endl;
        }
    }
}

// handles ipv4 errors
// returns true if we reached destination or a error occured
bool Trace::handleIPv4Err(struct timeval elapsed, struct sock_extended_err *sock_err) {
    bool end = false;

    // time exceeded -> we got icmp back because of ttl -> print time
    if (sock_err->ee_type == ICMP_TIMXCEED) {
        cout << "   " << elapsed.tv_usec / (double) 1000 << "ms";
    } else if (sock_err->ee_type == ICMP_UNREACH) { // unreachable -> lets handle some errors
        switch (sock_err->ee_code) {
            case ICMP_UNREACH_NET: { // unreachable net -> print N!
                end = true;
                cout << "   N!";
                break;
            }

            case ICMP_UNREACH_NET_PROHIB:
            case ICMP_UNREACH_HOST_PROHIB:
            case ICMP_UNREACH_FILTER_PROHIB: { // access prohibited -> print X!
                end = true;
                cout << "   X!";
                break;
            }

            case ICMP_UNREACH_HOST: { // host unreachable -> print H!
                end = true;
                cout << "   H!";
                break;
            }

            case ICMP_UNREACH_PROTOCOL: { // protocol unreachable -> print P!
                end = true;
                cout << "   P!";
                break;
            }

            case ICMP_UNREACH_PORT: { // port unreachable -> bingo, we reached our destination -> print time and end;
                end = true;
                cout << "   " << elapsed.tv_usec / (double) 1000 << "ms";
                break;
            }

            default: { // every else error -> print unknown!
                end = true;
                cout << " unknown!";
                break;
            }
        }
    }

    return end;
}

// handles ipv6 errors
// returns true if we reached destination or a error occured
bool Trace::handleIPv6Err(struct timeval elapsed, struct sock_extended_err *sock_err) {
    bool end = false;

    // time exceed error
    if (sock_err->ee_type == 3) {
        cout << "   " << elapsed.tv_usec / (double) 1000 << "ms";
    } else if (sock_err->ee_type == 1) { // unreachable error
        switch (sock_err->ee_code) {
            case 0: { // unreachable network -> print N!
                end = true;
                cout << "   N!";
                break;
            }

            case 1: { // access prohibited -> print X!
                end = true;
                cout << "   X!";
                break;
            }

            case 3: { // host unreachable -> print H!
                end = true;
                cout << "   H!";
                break;
            }

            case 4: { // port unreachable -> bingo, we reached our destination -> print time and end;
                end = true;
                cout << "   " << elapsed.tv_usec / (double) 1000 << "ms";
                break;
            }

            default: {
                end = true;
                cout << "   unknown (" << (int) sock_err->ee_code << ")!";
                break;
            }
        }
    } else if (sock_err->ee_type == 4 && sock_err->ee_code == 1) {
        end = true;
        cout << "   P!"; // protocol unreachable -> print P!
    }

    return end;
}

int main(int argc, char **argv) {

    int ttl = 1;
    int m_ttl = 30;

    if (argc % 2 != 0) {
        cout << "Wrong number of arguments." << endl;
        return -34;
    }

    // arguments parsing
    for (int i = 1; i < argc; i++) {
        string arg(argv[i]);

        if (arg == "-m" && i < argc) {
            if (i + 1 == argc) {
                cout << "Wrong -m (max ttl) argument." << endl;
                return -30;
            }
            m_ttl = (int) strtoumax(argv[i + 1], NULL, 10);

            if (!isNumber(argv[i + 1]) || m_ttl < 0 || (errno == ERANGE)) {
                cout << "Wrong format of -m (max ttl) argument." << endl;
                return -31;
            }
        } else if (arg == "-f" && i < argc) {
            if (i + 1 == argc) {
                cout << "Wrong -f (ttl) argument." << endl;
                return -32;
            }
            ttl = (int) strtoumax(argv[i + 1], NULL, 10);

            if (!isNumber(argv[i + 1]) || ttl < 0 || (errno == ERANGE)) {
                cout << "Wrong format of -f (ttl) argument." << endl;
                return -33;
            }
        }
    }

    string addr(argv[argc - 1]);

    try {
        Trace trace(addr, ttl, m_ttl);
        trace.run();
    } catch (TraceException &error) {
        cout << error.getMessage() << endl;
        return error.getCode();
    }

    return 0;
}