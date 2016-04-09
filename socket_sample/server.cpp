/*
** echo_server.c -- Demo program: echo server
**
** Author: atctam
**
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>   /* for perror() */
#include <string.h>
/* for using socket functions */
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>


#define MYPORT 49952    // the server port number
                  // it must be unique within the server host machine
                  // you can change this number to a port number 
                  // within your allocated range

#define BACKLOG 10     // how many pending connections queue will hold

#define MAXDATASIZE 100 // max number of bytes we can get at once 


int main(void)
{
    int sockfd, new_fd, numbytes;  // listen on sock_fd, new connection on new_fd
    struct sockaddr_in my_addr;    // my address information
    struct sockaddr_in peer_addr;  // client's address information
    socklen_t sin_size;
    char buf[MAXDATASIZE];

   /* Create the socket for TCP communication */
   /* For the exercise, change this part to use UDP */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        exit(1);
    }

   /* Prepare the socket address structure of the server 
   */    
    my_addr.sin_family = AF_INET;         // host byte order
    my_addr.sin_port = htons(MYPORT);     // short, network byte order
    my_addr.sin_addr.s_addr = htonl(INADDR_ANY); // automatically fill with my IP address
    memset(&(my_addr.sin_zero), '\0', 8); // zero the rest of the struct

   /* Associate my address info to the socket */
    if (bind(sockfd, (struct sockaddr *)&my_addr, sizeof(struct sockaddr)) == -1) {
        perror("bind");
        exit(1);
    }

   /* Set up the listen queue for TCP server socket */
   /* For the exercise, you can comment out (remove) this part */
    if (listen(sockfd, BACKLOG) == -1) {
        perror("listen");
        exit(1);
    }

   /* For TCP server socket, block waiting for incoming connection */
   /* For the exercise, you can comment out (or remove) this part */
   {
      sin_size = sizeof(struct sockaddr_in);
      if ((new_fd = accept(sockfd, (struct sockaddr *)&peer_addr, &sin_size)) == -1) {
         perror("accept");
         exit(1);
      }
      printf("server: got connection from %s\n",inet_ntoa(peer_addr.sin_addr));
   }
   
   /* For TCP socket, ommunicate with the client using new_fd */
   /* First, blocing waiting for message and then send back the message */
   /* For the exercise, you have to comment out (or remove) the whole if/else block */
    if ((numbytes=recv(new_fd, buf, MAXDATASIZE-1, 0)) == -1) {
        perror("recv");
        exit(1);
    } else if (numbytes > 0) {
   /* if client side's connection is closed with bruteforce, recv() will return '0'
   */
      buf[numbytes]='\0';
      printf("\tReceived: %s\n", buf);
        
      /* echo the message back */
        if (send(new_fd, buf, numbytes, 0) == -1)
            perror("send");

   }

   /* For the exercise, add the code for communication using UDP in here */
   /* First, add a recvfrom() statement to get the message as well as 
      the client's address info */
   /* Second, add two printf() statements to print out client info and 
      the message */
   /* Third, add a sendto() statement to send back the message to the
      client process */
      
      
   /* close the sockets */
    close(new_fd);   // remove this one for the exercise
   close(sockfd);
   
   /* For the exercise, you can comment out (or remove) this part */
    printf("Close connection.\n\n");
   /* For the exercise, uncomment this part */
   /* printf("Finished\n"); */


    return 0;
}

