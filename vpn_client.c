#include <stdio.h>      // for printf() and fprintf() 
#include <sys/socket.h> // for socket(), connect(), send(), and recv() 
#include <arpa/inet.h>  // for sockaddr_in and inet_addr() 
#include <stdlib.h>     // for atoi() and exit() 
#include <string.h>     // for memset() 
#include <unistd.h>     // for close() 
#include <sys/ioctl.h>      // ioctl
#include <linux/if_tun.h>   // tun/tap
#include <net/if.h>         // struct ifreq
#include <sys/types.h>      // open
#include <sys/stat.h>       // open
#include <fcntl.h>          // open
#include <errno.h>
#include <sys/epoll.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define BUFSIZE 1024 // Size of receive buffer 

int tun_alloc( char *dev, int flags )
{
    struct ifreq ifr;
    int fd, err;
    char *clonedev = "/dev/net/tun";

    if( ( fd = open( clonedev , O_RDWR ) ) < 0 ) 
    {
        perror( "Opening /dev/net/tun" );
        return fd;
    }

    memset( &ifr, 0, sizeof( ifr ) );

    ifr.ifr_flags = flags;
    
    // Set the interface name.
    if ( strlen( dev ) > 0 ) 
    {
        strncpy( ifr.ifr_name, dev, IFNAMSIZ );
    }

    if( ( err = ioctl( fd, TUNSETIFF, (void *)&ifr ) ) < 0 ) 
    {
        perror( "ioctl(TUNSETIFF)" );
        close( fd );
        return err;
    }

    return fd;
}

int tun_set_ip( char *dev, char *ipaddr, char *netmask )
{
    struct ifreq ifr;
    int err;
    
    // ioctl needs one fd as an input.
    // Request kernel to give me an unused fd. 
    int fd = socket( PF_INET, SOCK_DGRAM, IPPROTO_IP );
    
    // Set the interface name.
    if ( *dev ) 
    {
        strncpy( ifr.ifr_name, dev, IFNAMSIZ );
    }
    ifr.ifr_addr.sa_family = AF_INET;
    
    // Set IP address
    // The structure of ifr.ifr_addr.sa_data is "struct sockaddr"
    // struct sockaddr
    // {
    //      unsigned short    sa_family;
    //      char              sa_data[14];
    // }
    // This is why +2 is used.
    if( ( err = inet_pton( AF_INET, ipaddr, ifr.ifr_addr.sa_data + 2 ) ) != 1 )
    {
        perror( "Error IP address." );
        close( fd );
        return err;
    }
    if( ( err = ioctl( fd, SIOCSIFADDR, &ifr ) ) < 0 )
    {
        perror( "IP: ioctl(SIOCSIFADDR)" );
        close( fd );
        return err;
    }
    
    // Set netmask
    if( ( err = inet_pton( AF_INET, netmask, ifr.ifr_addr.sa_data + 2 ) ) != 1 )
    {
        perror( "Error IP address." );
        close( fd );
        return err;
    }
    if( ( err = ioctl( fd, SIOCSIFNETMASK, &ifr ) ) < 0 )
    {
        perror( "Netmask: ioctl(SIOCSIFNETMASK)" );
        close( fd );
        return err;
    }
    
    // Enable the interface
    // Get the interface flag first and add IFF_UP | IFF_RUNNING.
    if( ( err = ioctl( fd, SIOCGIFFLAGS, &ifr ) ) < 0 )
    {
        perror( "ioctl(SIOCGIFFLAGS)" );
        close( fd );
        return err;
    }
    ifr.ifr_flags |= ( IFF_UP | IFF_RUNNING );
    if( ( err = ioctl( fd, SIOCSIFFLAGS, &ifr ) ) < 0 )
    {
        perror( "ioctl(SIOCSIFFLAGS)" );
        close( fd );
        return err;
    }
    
    close( fd );
    
    return 1;
}

int read_chk(int fd, char *buf, int len)
{
    int n = 0;
    if((n = read(fd, buf, len)) < 0)
    {
        perror("read");
        exit(1);
    }
    return n;
}

int write_chk(int fd, char *buf, int len)
{
    int n = 0;
    if((n = write(fd, buf, len)) < 0)
    {
        perror("write");
        exit(1);
    }
    return n;
}

int SSL_read_chk(SSL *ssl, char *buffer, int len)
{
    int n = 0;
    if ( ( n = SSL_read( ssl, buffer, len) ) <= 0 )
    {
        perror("recv() failed or connection closed prematurely");
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    return n;
}

int SSL_write_chk(SSL *ssl, char *buffer, int len)
{
    int n = 0;
    if ( (n = SSL_write(ssl, buffer, len)) <= 0 )
    {
        perror( "send() sent a different number of bytes than expected");
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    return n;
}

int main(int argc, char *argv[])
{
    int sock;                        // Socket descriptor 
    struct sockaddr_in echoServAddr; // Echo server address 
    unsigned short echoServPort;     // Echo server port 
    char *servIP;                    // Server IP address (dotted quad)
    char buffer[BUFSIZE];            // Buffer for echo string  
    unsigned int echoStringLen;      // Length of string to echo 
    int bytesRcvd, totalBytesRcvd;   // Bytes read in single recv() and total bytes read 

    char tap_ifname[IFNAMSIZ];
    char tap_ipaddr[16];
    char tap_netmask[16];
    int tap_fd = 0;

    if ( argc != 4 )    // Test for correct number of arguments 
    {
       fprintf( stderr, "Usage: %s <Server IP> <Echo Port> <Tap IP>\n", argv[0] );
       exit(1);
    }

    servIP = argv[1];             // First arg: server IP address (dotted quad) 
    echoServPort = atoi(argv[2]); 

    strncpy(tap_ifname, "tap0", IFNAMSIZ - 1);
    strncpy(tap_ipaddr, argv[3], 15);
    strncpy(tap_netmask, "255.255.255.0", 15);

    if( ( tap_fd = tun_alloc( tap_ifname, IFF_TAP | IFF_NO_PI ) ) < 0 )
    {
        printf( "Create TUN/TAP interface fail!!\n" );
    }

    if (tun_set_ip( tap_ifname, tap_ipaddr, tap_netmask ) != 1)
    {
        printf("Set TUN/TAP interface fail!!\n");
    }

    // Create a reliable, stream socket using TCP 
    if ( ( sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP ) ) < 0 )
    {
        perror("socket() failed");
        exit(1);
    }
    
    // Construct the server address structure 
    memset(&echoServAddr, 0, sizeof(echoServAddr));     // Zero out structure 
    echoServAddr.sin_family      = AF_INET;             // Internet address family 
    echoServAddr.sin_addr.s_addr = inet_addr(servIP);   // Server IP address 
    echoServAddr.sin_port        = htons(echoServPort); // Server port 

    // Establish the connection to the echo server 
    if ( connect( sock, (struct sockaddr *) &echoServAddr, sizeof( echoServAddr ) ) < 0 )
    {
        perror( "connect() failed" );
        exit(1);
    }
    
    // Initialize OpenSSL
    SSL_load_error_strings();   
    OpenSSL_add_ssl_algorithms();
    
    const SSL_METHOD *method;
    method = TLS_client_method();
    SSL_CTX *ctx;
    ctx = SSL_CTX_new( method );
    
    if( !ctx )
    {
        perror( "Unable to create SSL context" );
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    
    SSL *ssl = SSL_new( ctx );
    SSL_set_fd( ssl, sock );
    
    if ( SSL_connect( ssl ) < 0 )
    {
        perror( "Unable to setup an SSL connection" );
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    #define MAXEV 3

    int                     epfd;                   // EPOLL File Descriptor. 
    struct epoll_event      ev;                     // Used for EPOLL.
    struct epoll_event      events[MAXEV];  // Used for EPOLL.
    int                     noEvents;               // EPOLL event number.
    
    epfd = epoll_create1( 0 );		
    
    // Add the server socket to the epoll
    ev.data.fd = tap_fd;
    ev.events = EPOLLIN;
    epoll_ctl( epfd, EPOLL_CTL_ADD, tap_fd, &ev );

    ev.data.fd = sock;
    ev.events = EPOLLIN;
    epoll_ctl( epfd, EPOLL_CTL_ADD, sock, &ev );
    
    // Add STDIN into the EPOLL set.
    ev.data.fd = STDIN_FILENO;
    ev.events = EPOLLIN;
    epoll_ctl( epfd, EPOLL_CTL_ADD, STDIN_FILENO, &ev );  

    int running = 1;
    int n = 0;
    int plength = 0;
    while( running )
    {
        noEvents = epoll_wait( epfd, events, MAXEV , ( 5 * 1000 ) );
        
        if ( noEvents <= 0 ) 
        {
            printf("No echo requests for 5 secs...Server still alive\n" );
            continue; 
        }
        
        for( int i = 0 ; i < noEvents ; i++ )
        {
            if( events[i].events & EPOLLIN && STDIN_FILENO == events[i].data.fd )
            {
                printf("Shutting down server\n");
                getchar();
                running = 0;
                continue;
            }
            if ( events[i].events & EPOLLIN && sock == events[i].data.fd )
            {
                if (SSL_read_chk(ssl, (char *)&plength, sizeof(plength)) == 0)
                {
                    break;
                }

                n = SSL_read_chk(ssl, buffer, ntohs(plength));
                write_chk(tap_fd, buffer, n);
            }
            if ( events[i].events & EPOLLIN && tap_fd == events[i].data.fd  )
            {
                bzero(buffer, BUFSIZE);
                n = read_chk(tap_fd, buffer, BUFSIZE);

                plength = htons(n);
                SSL_write_chk(ssl, (char *)&plength, sizeof(plength));
                SSL_write_chk(ssl, buffer, n);
            }
        }
    }
    
    printf("\n");    // Print a final linefeed 
    
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx); 
    close(tap_fd);
    return 0;
}