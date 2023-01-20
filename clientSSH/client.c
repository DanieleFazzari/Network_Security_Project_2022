#include <libssh/libssh.h>
#include <semaphore.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>

int direct_forward(ssh_session session){
  ssh_channel channel;
  int port_source, port_destination;
  char host_destination[256];
  int rc;
  int nbytes;
  char buffer[256];
  int nwritten;

  printf("Insert the port to forward: ");
  scanf("%d", &port_source);
  printf("Insert the destination host: ");
  scanf("%s", host_destination);
  printf("Insert the destination port: ");
  scanf("%d", &port_destination);

  int socket_desc, client_sock, client_size;
	struct sockaddr_in server_addr, client_addr;
  
  socket_desc = socket(AF_INET, SOCK_STREAM, 0);
  if (socket_desc == -1){
    printf("Could not create socket");
  }

  server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = INADDR_ANY;
  server_addr.sin_port = htons(port_source);  

  if (bind(socket_desc, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0){
    perror("bind failed. Error");
    return -1;
  }

  printf("Socket ready\n");
	
  channel = ssh_channel_new(session);
  if (channel == NULL) return SSH_ERROR;

  rc = ssh_channel_open_forward(channel, host_destination, port_destination, "localhost", port_source);
  if (rc != SSH_OK){
    ssh_channel_free(channel);
    return rc;
  }

  printf("Forwarding port %d to %s:%d\n", port_source, host_destination, port_destination);

  listen(socket_desc, 1);

  printf("Waiting for incoming connections...\n");

  client_size = sizeof(struct sockaddr_in);
  client_sock = accept(socket_desc, (struct sockaddr *)&client_addr, (socklen_t*)&client_size);

  if (client_sock < 0){
    perror("accept failed");
    return 1;
  }

  printf("Connection accepted\n");

  int connected = 1;

  while(ssh_channel_is_open(channel) && !ssh_channel_is_eof(channel)){
      
    //non blocking receive on the socket
    nbytes = recv(client_sock, buffer, sizeof(buffer), MSG_DONTWAIT);
    if (nbytes > 0){
      nwritten = ssh_channel_write(channel, buffer, nbytes);
    } else if(nbytes == 0){
      connected = 0;
      close(client_sock);
      close(socket_desc);
    }
      
    nbytes = ssh_channel_read_nonblocking(channel, buffer, sizeof(buffer), 0);
    if (nbytes < 0) return SSH_ERROR;
    if (nbytes > 0){
      nwritten = write(client_sock, buffer, nbytes);
      if (nwritten != nbytes) return SSH_ERROR;
    }  
  }

  ssh_channel_send_eof(channel);
  ssh_channel_close(channel);
  ssh_channel_free(channel);
  return 1;
}

int remote_shell(ssh_session my_ssh_session){
  char buffer[256];
  int nbytes,nwritten,rc;

  ssh_channel channel;
  channel = ssh_channel_new(my_ssh_session);
  if (channel == NULL) return SSH_ERROR;
  
  rc = ssh_channel_open_session(channel);
  if (rc != SSH_OK){
    ssh_channel_free(channel);
    return rc;
  }
 
  rc = ssh_channel_request_pty(channel);
  if (rc != SSH_OK) return rc;
 
  rc = ssh_channel_change_pty_size(channel, 80, 24);
  if (rc != SSH_OK) return rc;
 
  rc = ssh_channel_request_shell(channel);
  if (rc != SSH_OK) return rc;
 
   while (ssh_channel_is_open(channel) && !ssh_channel_is_eof(channel)){
		struct timeval timeout;
		ssh_channel in_channels[2], out_channels[2];
		fd_set fds;
		int maxfd;
	 
		timeout.tv_sec = 30;
		timeout.tv_usec = 0;
		in_channels[0] = channel;
		in_channels[1] = NULL;
		FD_ZERO(&fds);
		FD_SET(0, &fds);
		FD_SET(ssh_get_fd(my_ssh_session), &fds);
		maxfd = ssh_get_fd(my_ssh_session) + 1;
		ssh_select(in_channels, out_channels, maxfd, &fds, &timeout);
		if (out_channels[0] != NULL){
		  nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
		  if (nbytes < 0) return SSH_ERROR;
		  if (nbytes > 0){
		    nwritten = write(1, buffer, nbytes);
		    if (nwritten != nbytes) return SSH_ERROR;
		  }
		}
	 
		if (FD_ISSET(0, &fds)){
		  nbytes = read(0, buffer, sizeof(buffer));
		  if (nbytes < 0) return SSH_ERROR;
		  if (nbytes > 0)
{
		    nwritten = ssh_channel_write(channel, buffer, nbytes);
		    if (nbytes != nwritten) return SSH_ERROR;
		  }
		}
  }
  
  ssh_channel_send_eof(channel);
  ssh_channel_close(channel);
  ssh_channel_free(channel);
}

int exec_command(ssh_session session){
  ssh_channel channel;
  int rc;
  channel = ssh_channel_new(session);
  if (channel == NULL) return SSH_ERROR;
  rc = ssh_channel_open_session(channel);
  if (rc != SSH_OK){
    ssh_channel_free(channel);
    return rc;
  }

  char cmd[256];
  
  // clear the stdin
  while (getchar() != '\n');

  printf("Enter command: ");
  fgets(cmd, sizeof(cmd), stdin);

  rc = ssh_channel_request_exec(channel, cmd);
  if (rc != SSH_OK){
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    return rc;
  }
  char buffer[256];
  int nbytes;

  nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
  while (nbytes > 0){
    if (fwrite(buffer, 1, nbytes, stdout) != nbytes){
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    return SSH_ERROR;
  }
  nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
  }

  if (nbytes < 0){
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    return SSH_ERROR;
  }
  ssh_channel_send_eof(channel);
  ssh_channel_close(channel);
  ssh_channel_free(channel);

  return SSH_OK;
}

int authenticate_console(ssh_session session){
  int rc;
  int method;
  char password[128] = {0};
  char *banner;

	int mode;
  do{
		printf("Inserisci il metodo di autenticazione \n");
		printf("1-None \n2-Publick Key\n3-Username e Password\n");
		scanf("%d",&mode);
		if(mode==1)
    		rc = ssh_userauth_none(session, NULL);
		
		else if(mode==2)
      rc = ssh_userauth_publickey_auto(session, NULL, NULL);
		
		else if(mode==3){
      char *password2;
	    char usrn[50];
		  printf("Username: ");         
      scanf("%s",usrn);
		  password2 = getpass("Password: ");
		  rc = ssh_userauth_password(session, usrn , password2);
    }
  }while(rc != SSH_AUTH_SUCCESS);
    
	return rc; 
}

int verify_knownhost(ssh_session session){
    enum ssh_known_hosts_e state;
    unsigned char *hash = NULL;
    ssh_key srv_pubkey = NULL;
    size_t hlen;
    char buf[10];
    char *hexa;
    char *p;
    int cmp;
    int rc;
 
    rc = ssh_get_server_publickey(session, &srv_pubkey);
    if (rc < 0) {
        return -1;
    }
 
    rc = ssh_get_publickey_hash(srv_pubkey,SSH_PUBLICKEY_HASH_SHA1,&hash,&hlen);
    ssh_key_free(srv_pubkey);
    if (rc < 0) {
      return -1;
    }
 
    state = ssh_session_is_known_server(session);
    switch (state) {
      case SSH_KNOWN_HOSTS_OK:
        break;
      case SSH_KNOWN_HOSTS_CHANGED:
        fprintf(stderr, "Host key for server changed: it is now:\n");
        ssh_print_hexa("Public key hash", hash, hlen);
        fprintf(stderr, "For security reasons, connection will be stopped\n");
        ssh_clean_pubkey_hash(&hash);
        return -1;
      case SSH_KNOWN_HOSTS_OTHER:
        fprintf(stderr, "The host key for this server was not found but an other"
                    "type of key exists.\n");
        fprintf(stderr, "An attacker might change the default server key to"
                    "confuse your client into thinking the key does not exist\n");
        ssh_clean_pubkey_hash(&hash);
        return -1;
      case SSH_KNOWN_HOSTS_NOT_FOUND:
        fprintf(stderr, "Could not find known host file.\n");
        return -1; 
      case SSH_KNOWN_HOSTS_UNKNOWN:
        hexa = ssh_get_hexa(hash, hlen);
        fprintf(stderr,"The server is unknown. Do you trust the host key?\n");
        fprintf(stderr, "Public key hash: %s\n", hexa);
        ssh_string_free_char(hexa);
        ssh_clean_pubkey_hash(&hash);
        p = fgets(buf, sizeof(buf), stdin);
        if (p == NULL) {
          return -1;
        }
        cmp = strncasecmp(buf, "yes", 3);
        if (cmp != 0) 
          return -1;
        rc = ssh_session_update_known_hosts(session);
          if (rc < 0) {
            fprintf(stderr, "Error %s\n", strerror(errno));
            return -1;
          }
          break;
        case SSH_KNOWN_HOSTS_ERROR:
          fprintf(stderr, "Error %s", ssh_get_error(session));
          ssh_clean_pubkey_hash(&hash);
          return -1;
    }
    ssh_clean_pubkey_hash(&hash);
    return 0;
}

int main(){
  ssh_session my_ssh_session;
  int rc;
  char *password;
 
  // Open session and set options
  my_ssh_session = ssh_new();
  if (my_ssh_session == NULL)
    exit(-1);
  ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, "localhost");
  ssh_options_set(my_ssh_session, SSH_OPTIONS_CIPHERS_C_S, "aes128-cbc");
  ssh_options_set(my_ssh_session, SSH_OPTIONS_CIPHERS_S_C, "aes128-cbc");
  // Connect to server
  rc = ssh_connect(my_ssh_session);
  if (rc != SSH_OK){
    fprintf(stderr, "Error connecting to localhost: %s\n",
    ssh_get_error(my_ssh_session));
    ssh_free(my_ssh_session);
    exit(-1);
  }
 
  if (verify_knownhost(my_ssh_session) < 0){
    ssh_disconnect(my_ssh_session);
    ssh_free(my_ssh_session);
    exit(-1);
  }

  rc = authenticate_console(my_ssh_session);
  
  printf("Select mode: \n");
  printf("1. Remote Shell\n");
  printf("2. Direct Forwarding\n");
  printf("3. Exec command\n");

  int mode;
  scanf("%d",&mode);
  
  if(mode==1)
    remote_shell(my_ssh_session);
  else if(mode==2)
    direct_forward(my_ssh_session);
  else if(mode==3)
    exec_command(my_ssh_session);
  else
    printf("Invalid mode...\n");

  ssh_disconnect(my_ssh_session);
  ssh_free(my_ssh_session);
}
