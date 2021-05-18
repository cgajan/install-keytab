/* ================================================================== */
/* Name: push-keytab.c                                                */
/* Version: 1.0.5                                                     */
/* Author: Christian Gajan                                            */
/* Date: 29 April 2021                                                */
/* ================================================================== */
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <libssh/libssh.h>

#define KEYTABLIMIT 4096
#define KEYTABENV "_INFORMATION_"
#define REMOTECMD "/usr/bin/install-keytab -e"

#define READ_ERR 110
#define FILE_ERR 111
#define REMOTE_CMD_ERR 112

#define DEFAULT_DEBUG_MODE 0

#define RED "\033[0;31m"
#define GREEN "\033[0;32m"
#define ORANGE "\033[0;33m"
#define PURPLE "\033[0;35m"
#define LRED "\033[1;31m"
#define LGREEN "\033[1;32m"
#define LORANGE "\033[1;33m"
#define LBLUE "\033[1;34m"
#define LPURPLE "\033[1;35m"
#define NC "\033[0m"

#define DEBUG_COLOR LPURPLE
#define ERROR_COLOR LRED
#define WARN_COLOR LORANGE
#define INFO_COLOR LGREEN
#define REMOTE_ERR_COLOR ORANGE

int debug = DEFAULT_DEBUG_MODE;
char *debugColor = DEBUG_COLOR;
char *errorColor = ERROR_COLOR;
char *warnColor = WARN_COLOR;
char *infoColor = INFO_COLOR;
char *errRemoteColor = REMOTE_ERR_COLOR;
char *errResetColor = NC;
char *outResetColor = NC;

/* ------------------------------ */
/* CONSTANTS FORM BASE64 ENCODING */
/* ------------------------------ */
const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/*=========================================================
 * PRINT THE COMMAND USAGE
 * ======================================================== */
void usage(char *cname)
{
   fprintf(stderr, "usage: %s -k keytab -h host [-p port]\n", cname);
}
/*========================================================= */


/*=========================================================
 * Base64 utility function
 * ======================================================== */
size_t b64_encoded_size(size_t inlen)
{
   size_t ret;

   ret = inlen;
   if (inlen % 3 != 0) ret += 3 - (inlen % 3);
   ret /= 3;
   ret *= 4;

   return ret;
}
/*========================================================= */

/*=========================================================
 * Base64 encoding function 
 * ======================================================== */
char *b64_encode(const unsigned char *in, size_t len)
{
   char   *out;
   size_t  elen;
   size_t  i;
   size_t  j;
   size_t  v;

   if (in == NULL || len == 0) return NULL;

   elen = b64_encoded_size(len);
   out  = malloc(elen+1);
   out[elen] = '\0';

   for (i=0, j=0; i<len; i+=3, j+=4) {
      v = in[i];
      v = i+1 < len ? v << 8 | in[i+1] : v << 8;
      v = i+2 < len ? v << 8 | in[i+2] : v << 8;

      out[j]   = b64chars[(v >> 18) & 0x3F];
      out[j+1] = b64chars[(v >> 12) & 0x3F];
      if (i+1 < len) {
         out[j+2] = b64chars[(v >> 6) & 0x3F];
      } else {
         out[j+2] = '=';
      }
      if (i+2 < len) {
         out[j+3] = b64chars[v & 0x3F];
      } else {
         out[j+3] = '=';
      }
   }

   return out;
}
/*========================================================= */

/*=========================================================
 * VERIFY SSH REMOTE HOST AUTHENTICATION 
 * ======================================================== */
int verify_knownhost(ssh_session session)
{
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

   rc = ssh_get_publickey_hash(srv_pubkey, SSH_PUBLICKEY_HASH_SHA1, &hash, &hlen);
   ssh_key_free(srv_pubkey);
   if (rc < 0) {
      return -1;
   }

   state = ssh_session_is_known_server(session);
   switch (state) {
      case SSH_KNOWN_HOSTS_OK:
         /* OK */
         break;

      case SSH_KNOWN_HOSTS_CHANGED:
         fprintf(stderr, "%sHost key for server changed: it is now:%s\n", errorColor, errResetColor);
         ssh_print_hash(SSH_PUBLICKEY_HASH_SHA256, hash, hlen);
         fprintf(stderr, "%sFor security reasons, connection will be stopped%s\n", errorColor, errResetColor);
         ssh_clean_pubkey_hash(&hash);
         return -1;

      case SSH_KNOWN_HOSTS_OTHER:
         fprintf(stderr, "%sThe host key for this server was not found but an other type of key exists.%s\n", errorColor, errResetColor);
         fprintf(stderr, "%sAn attacker might change the default server key to%s\n", errorColor, errResetColor);
         fprintf(stderr, "%sconfuse your client into thinking the key does not exist%s\n", errorColor, errResetColor);
         ssh_clean_pubkey_hash(&hash);
         return -1;

      case SSH_KNOWN_HOSTS_NOT_FOUND:
         fprintf(stderr, "%sCould not find known host file.%s\n", warnColor, errResetColor);
         fprintf(stderr, "%sIf you accept the host key here, the file will be automatically created.%s\n", warnColor, errResetColor);
         /* FALL THROUGH to SSH_SERVER_NOT_KNOWN behavior */

      case SSH_KNOWN_HOSTS_UNKNOWN:
         hexa = ssh_get_hexa(hash, hlen);
         fprintf(stderr, "%sThe server is unknown. Do you trust the host key?%s\n", warnColor, errResetColor);
         fprintf(stderr, "%sPublic key hash: %s%s\n", warnColor, errResetColor, hexa);
         fprintf(stderr, "%sDo you accept this key [yes|no]: %s", warnColor, errResetColor);
         ssh_string_free_char(hexa);
         ssh_clean_pubkey_hash(&hash);
         p = fgets(buf, sizeof(buf), stdin);
         if (p == NULL) {
            return -1;
         }

         cmp = strncasecmp(buf, "yes", 3);
         if (cmp != 0) {
            return -1;
         }

         rc = ssh_session_update_known_hosts(session);
         if (rc < 0) {
            fprintf(stderr, "%sERROR: %s%s\n", errorColor, strerror(errno), errResetColor);
            return -1;
         }
         break;
      case SSH_KNOWN_HOSTS_ERROR:
         fprintf(stderr, "%sERROR: %s%s", errorColor, ssh_get_error(session), errResetColor);
         ssh_clean_pubkey_hash(&hash);
         return -1;
   }

   ssh_clean_pubkey_hash(&hash);
   return 0;
}
/*========================================================= */

/*=========================================================
 * PUSH THE KEYTAB THROUGH SSH 
 * ======================================================== */
int push_keytab(ssh_session session, char *source, int *rrc)
{
   ssh_channel channel;
   int rc;
   char sshbuffer[BUFSIZ];
   int nbytes;
   char *encoded;
   char cmd[2048];
   size_t len;
   FILE *in;
   char buffer[BUFSIZ];
   struct stat st;

  /* ------------------------------------------------------
   * Open a ssh channel
   * ------------------------------------------------------ */
   channel = ssh_channel_new(session);
   if (channel == NULL) {
      return SSH_ERROR;
   }

   rc = ssh_channel_open_session(channel);
   if (rc != SSH_OK)
   {
      ssh_channel_free(channel);
      return rc;
   }

   /* ------------------------------------------------ */
   /* Check if the keytab size is not too big          */
   /* ------------------------------------------------ */
   if (stat(source, &st) == 0) {
      if(st.st_size > KEYTABLIMIT) {
         fprintf(stderr, "%sERROR: keytab file size is too big to be pushed%s\n", errorColor, errResetColor);
         return FILE_ERR;
      }
   } else {
      fprintf(stderr, "%sERROR: keytab file not found%s\n", errorColor, errResetColor);
      return FILE_ERR;
   } 

   /* ------------------------------------------------ */
   /* Open the keytab file                             */
   /* ------------------------------------------------ */
   in = fopen(source, "rb" ) ;
   if(in == NULL)
   {
      fprintf(stderr, "%sERROR: cannot open source keytab file: %s%s\n", errorColor, strerror(errno), errResetColor);
      return FILE_ERR;
   }

   /* -------------------------------------------------- */
   /* Read the keytab and encode the content in a buffer */
   /* Then exec the remote utility by forwarding the     */
   /* encoded keypas through an environment variable     */
   /* -------------------------------------------------- */
   len = fread(buffer, 1, BUFSIZ, in);
   if(len == 0 && ferror(in) != 0) {
      fprintf(stderr, "%sERROR: cannot read keytab file: %s%s\n", errorColor, strerror(errno), errResetColor);
      return READ_ERR;
   }
   encoded = b64_encode(buffer, len);
   sprintf(cmd, "%s=%s %s", KEYTABENV, encoded, REMOTECMD);
   rc = ssh_channel_request_exec(channel, cmd);
   if (rc != SSH_OK)
   {
      ssh_channel_close(channel);
      ssh_channel_free(channel);
      return rc;
   }

   /* ----------------------------------------------------------------- */
   /* analyze and display the remote command output                     */
   /* ----------------------------------------------------------------- */
   fprintf(stdout, "%s", infoColor); fflush(stdout);
   nbytes = ssh_channel_read(channel, sshbuffer, sizeof(sshbuffer), 0);
   while (nbytes > 0)
   {
      if (write(1, sshbuffer, nbytes) != (unsigned int) nbytes)
      {
         ssh_channel_close(channel);
         ssh_channel_free(channel);
         return SSH_ERROR;
       }
       nbytes = ssh_channel_read(channel, sshbuffer, sizeof(sshbuffer), 0);
   }
   fprintf(stdout, "%s", outResetColor); fflush(stdout);
   fprintf(stderr, "%s", errRemoteColor); fflush(stderr);
   nbytes = ssh_channel_read(channel, sshbuffer, sizeof(sshbuffer), 1);
   while (nbytes > 0)
   {
      if (write(2, sshbuffer, nbytes) != (unsigned int) nbytes)
      {
         ssh_channel_close(channel);
         ssh_channel_free(channel);
         return SSH_ERROR;
       }
       nbytes = ssh_channel_read(channel, sshbuffer, sizeof(sshbuffer), 1);
   }
   fprintf(stderr, "%s", errResetColor); fflush(stderr);

   if (nbytes < 0)
   {
      ssh_channel_close(channel);
      ssh_channel_free(channel);
      return SSH_ERROR;
   }
   rc = ssh_channel_get_exit_status(channel);
   if(rc != 0) {
      ssh_channel_send_eof(channel);
      ssh_channel_close(channel);
      ssh_channel_free(channel);
      fprintf(stderr, "%sERROR: remote installation fail with exit code %d%s\n", errorColor, rc, errResetColor);
      *rrc = rc;
      return REMOTE_CMD_ERR;
   }

   ssh_channel_send_eof(channel);
   ssh_channel_close(channel);
   ssh_channel_free(channel);
   return SSH_OK;
}
/*========================================================= */

/*=========================================================
 * MAIN
 * ======================================================== */
int main(int argc, char **argv)
{
   char *source = NULL;
   char *host = NULL;
   char *port = NULL;
   char buffer[BUFSIZ] = { '\0' } ;
   size_t len = 0 ;
   FILE* in ;
   int c;
   ssh_session my_ssh_session;
   int rc;
   int rrc = 0;
   char *password;
   int istty;

   /* ------------------------------------------------
    * Set color if it is a terminal
    * ------------------------------------------------ */ 
   istty = isatty(fileno(stderr));
   debugColor = istty ? DEBUG_COLOR : "";
   errorColor = istty ? ERROR_COLOR : "";
   warnColor = istty ? WARN_COLOR : "";
   errRemoteColor = istty ? REMOTE_ERR_COLOR : "";
   errResetColor = istty ? NC : "";
   istty = isatty(fileno(stdout));
   infoColor = istty ? INFO_COLOR : "";
   outResetColor = istty ? NC : "";

   /* ---------------------------------------------------
    * Command Parameters Parsing
    * --------------------------------------------------- */
   while ((c = getopt (argc, argv, "dk:h:p:")) != -1)
      switch (c) {
         case 'd':
            debug = 1;
            break;
         case 'k':
            source = optarg;
            break;
         case 'h':
            host = optarg;
            break;
         case 'p':
            port = optarg;
            break;
         default:
            usage(argv[0]);
            exit(-1);
      }
   if(source == NULL) {
      usage(argv[0]);
      exit(-1);
   }
   if(host == NULL) {
      usage(argv[0]);
      exit(-1);
   }

   /* ---------------------------------------------------- */
   /* Try to protect source keytab file                    */
   /* ---------------------------------------------------- */
   if(chmod(source, S_IRUSR|S_IWUSR) == -1)
   {
      fprintf(stderr, "%sWARNING: cannot protect the source keytab file: %s%s\n", warnColor, strerror(errno), errResetColor);
   }

   /* ------------------------------------------------------
    * Open session and set options
    * ------------------------------------------------------ */
   my_ssh_session = ssh_new();
   if (my_ssh_session == NULL) {
      exit(-1);
   }
   ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, host);
   if(port != NULL) {
      rc = ssh_options_set(my_ssh_session, SSH_OPTIONS_PORT_STR, port);
      if (rc != SSH_OK) {
         fprintf(stderr, "%sERROR: fail to connect to host: %s%s\n", errorColor, ssh_get_error(my_ssh_session), errResetColor);
         ssh_free(my_ssh_session);
         exit(-1);
      }
   }

   /* ------------------------------------------------------
    * Connect to server
    * ------------------------------------------------------ */
   rc = ssh_connect(my_ssh_session);
   if (rc != SSH_OK)
   {
      fprintf(stderr, "%sERROR: fail to connect to localhost: %s%s\n", errorColor, ssh_get_error(my_ssh_session), errResetColor);
      ssh_free(my_ssh_session);
      exit(rc);
   }

   /* ----------------------------------------------------------------------
    * Verify the server's identity
    * For the source code of verify_knownhost(), check previous example
    * ---------------------------------------------------------------------- */
   if (verify_knownhost(my_ssh_session) < 0)
   {
      ssh_disconnect(my_ssh_session);
      ssh_free(my_ssh_session);
      exit(-1);
   }

   /* --------------------------------------------------------------------
    * Authentication by RSA key first then by password if failed
    * -------------------------------------------------------------------- */
   rc = ssh_userauth_publickey_auto(my_ssh_session, NULL, NULL);
   if (rc != SSH_AUTH_SUCCESS)
   {
      password = getpass("Password: ");
      rc = ssh_userauth_password(my_ssh_session, NULL, password);
      if (rc != SSH_AUTH_SUCCESS)
      {
         fprintf(stderr, "%sERROR: fail to authenticate with password: %s%s\n", errorColor, ssh_get_error(my_ssh_session), errResetColor);
         ssh_disconnect(my_ssh_session);
         ssh_free(my_ssh_session);
         exit(-1);
      }
   }

   /* --------------------------------------------------------------------
    * Push the keytab
    * -------------------------------------------------------------------- */
   rc = push_keytab(my_ssh_session, source, &rrc);
   if (rc != SSH_OK) {
      if((rc != FILE_ERR) && (rc != READ_ERR) && (rc != REMOTE_CMD_ERR)) fprintf(stderr, "%sERROR: fail to push keytab: %s%s\n", errorColor, ssh_get_error(my_ssh_session), errResetColor);
      else fprintf(stderr, "%sERROR: fail to push keytab%s\n", errorColor, errResetColor);
      ssh_disconnect(my_ssh_session);
      ssh_free(my_ssh_session);
      exit(rrc);
   }

   /* --------------------------------------------------------------------
    * Close the SSH connection
    * -------------------------------------------------------------------- */
   ssh_disconnect(my_ssh_session);
   ssh_free(my_ssh_session);
}
