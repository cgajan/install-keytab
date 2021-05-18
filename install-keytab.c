/* ================================================================== */
/* Name: install-keytab.c                                             */
/* Version: 1.0.5                                                     */
/* Author: Christian Gajan                                            */
/* Date: 29 April 2021                                                */
/* ================================================================== */
#include <libgen.h>
#include <errno.h>
#include <ctype.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <syslog.h>
#include <libgen.h>
#include <krb5.h>
#include <pwd.h>

#define CONF_FILE "/etc/install-keytab.conf"
#define KEYTABENV "_INFORMATION_"

#define CK_OK 0
#define CK_KO 1
#define CK_NOT_VALID_PRINCIPAL 11
#define CK_NOT_VALID 20
#define CK_NOT_FILE 30
#define CK_NO_FILE 31
#define CK_ERR_CONTEXT 32

#define PRINCIPAL_MASK 1
#define LOWER_MASK 2
#define UPPER_MASK 4
#define ETYPE_MASK 8
#define DOMAIN_MASK 16

#define FILTER_EMPTY "_EMPTY_"
#define FILTER_ALL 0
#define FILTER_USER 1
#define FILTER_UPPER 2
#define FILTER_LOWER 3

#define ACTION_ALLOW 0
#define ACTION_DENY 1
#define ACTION_WARNING 2
#define ACTION_REMOVE 3
#define ACTION_PERMS 4
#define ACTION_NONE 5

#define DEFAULT_DEBUG_MODE 0
#define DEFAULT_ETYPE_FILTER "aes256-cts-hmac-sha1-96"
#define DEFAULT_ETYPE_ACTION ACTION_WARNING
#define DEFAULT_PRINCIPAL_FILTER FILTER_USER
#define DEFAULT_PRINCIPAL_ACTION ACTION_DENY
#define DEFAULT_PRINCIPAL_CASE_FILTER FILTER_UPPER
#define DEFAULT_PRINCIPAL_CASE_ACTION ACTION_WARNING
#define DEFAULT_PRINCIPAL_DOMAIN_FILTER FILTER_EMPTY
#define DEFAULT_PRINCIPAL_DOMAIN_ACTION ACTION_ALLOW
#define DEFAULT_SIZE_FILTER 4096
#define DEFAULT_SIZE_ACTION ACTION_DENY
#define DEFAULT_DESTINATION_KEYTAB "/var/lib/gssproxy/clients/%U.keytab"
#define DEFAULT_SOURCE_KEYTAB_PROTECTION ACTION_PERMS

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

/* ------------------------------ */
/* CONSTANTS FORM BASE64 ENCODING */
/* ------------------------------ */
const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const int b64invs[] = { 62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58,
	59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4, 5,
	6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
	21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28,
	29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
	43, 44, 45, 46, 47, 48, 49, 50, 51 };

/* ------------------------------ */
/* GLOBAL CONFIGURATION VARIABLES */
/* ------------------------------ */
char *etype_filter = DEFAULT_ETYPE_FILTER ;
int etype_action = DEFAULT_ETYPE_ACTION ;
int principal_filter = DEFAULT_PRINCIPAL_FILTER;
int principal_action = DEFAULT_PRINCIPAL_ACTION;
int principal_case_filter = DEFAULT_PRINCIPAL_CASE_FILTER;
int principal_case_action = DEFAULT_PRINCIPAL_CASE_ACTION;
char *principal_domain_filter = DEFAULT_PRINCIPAL_DOMAIN_FILTER;
int principal_domain_action = DEFAULT_PRINCIPAL_DOMAIN_ACTION;
int size_filter = DEFAULT_SIZE_FILTER;
int size_action = DEFAULT_SIZE_ACTION;
char *destination_keytab = DEFAULT_DESTINATION_KEYTAB ;
int source_keytab_protection = DEFAULT_SOURCE_KEYTAB_PROTECTION;
int debug = DEFAULT_DEBUG_MODE;
char *debugColor = DEBUG_COLOR;
char *errorColor = ERROR_COLOR;
char *warnColor = WARN_COLOR;
char *infoColor = INFO_COLOR;
char *errResetColor = NC;
char *outResetColor = NC;

/*=========================================================
 * PRINT THE COMMAND USAGE                                  
 * ======================================================== */
void usage(char *cname)
{
   fprintf(stderr, "usage: %s [-e|-k keytab]\n", cname);
}
/*========================================================= */

/*=========================================================
 * Base64 decoding utility functions                                 
 * ======================================================== */
unsigned int count_set_bits(unsigned int n)
{
    unsigned int count = 0;
    while (n) {
        count += n & 1;
        n >>= 1;
    }
    return count;
}
/*========================================================= */

/*=========================================================
 * Base64 decoding utility functions                                 
 * ======================================================== */
size_t b64_decoded_size(const char *in)
{
   size_t len;
   size_t ret;
   size_t i;

   if (in == NULL)  return 0;
   len = strlen(in);
   ret = len / 4 * 3;
   for (i=len; i-->0; ) {
      if (in[i] == '=') {
         ret--;
      } else {
         break;
      }
   }
   return ret;
}
/* -------------------------------------------------------- */
void b64_generate_decode_table()
{
   int    inv[80];
   size_t i;

   memset(inv, -1, sizeof(inv));
   for (i=0; i<sizeof(b64chars)-1; i++) {
   inv[b64chars[i]-43] = i;
   }
}

/* -------------------------------------------------------- */
int b64_isvalidchar(char c)
{
   if (c >= '0' && c <= '9') return 1;
   if (c >= 'A' && c <= 'Z') return 1;
   if (c >= 'a' && c <= 'z') return 1;
   if (c == '+' || c == '/' || c == '=') return 1;
   return 0;
}
/*========================================================= */

/*=========================================================
 * Base64 decode function                            
 * ======================================================== */
int b64_decode(const char *in, unsigned char *out, size_t outlen)
{
   size_t len;
   size_t i;
   size_t j;
   int    v;

   if (in == NULL || out == NULL) return 0;
   len = strlen(in);
   if (outlen < b64_decoded_size(in) || len % 4 != 0) return 0;
   for (i=0; i<len; i++) {
      if (!b64_isvalidchar(in[i])) {
         return 0;
      }
   }
   for (i=0, j=0; i<len; i+=4, j+=3) {
      v = b64invs[in[i]-43];
      v = (v << 6) | b64invs[in[i+1]-43];
      v = in[i+2]=='=' ? v << 6 : (v << 6) | b64invs[in[i+2]-43];
      v = in[i+3]=='=' ? v << 6 : (v << 6) | b64invs[in[i+3]-43];

      out[j] = (v >> 16) & 0xFF;
      if (in[i+2] != '=') out[j+1] = (v >> 8) & 0xFF;
      if (in[i+3] != '=') out[j+2] = v & 0xFF;
   }
   return 1;
}
/*========================================================= */


/*=========================================================
 * Check Keytab                             
 * ======================================================== */
int check_keytab(const char *name,  char *username)
{
   krb5_context context;
   krb5_error_code ret;
   krb5_keytab kt;
   krb5_keytab_entry entry;
   krb5_kt_cursor cursor;
   unsigned int i;
   char buf[BUFSIZ];
   char uname[BUFSIZ];
   char lname[BUFSIZ];
   char *pname;
   char *ename;
   char *puser;
   char *pdomain;
   char *s;
   int cmask ;
   int wmask ;
   int selected ;
   int prevnbwarn ;
   int nbwarn ;
   int id ;

   if (name == NULL) {
      return CK_NO_FILE;
   }
   ret = krb5_init_context(&context);
   if (ret) {
      return CK_ERR_CONTEXT;
   }
   ret = krb5_kt_resolve(context, name, &kt);
   if (ret) {
      return CK_NOT_FILE;
   }

   ret = krb5_kt_get_name(context, kt, buf, BUFSIZ);
   if (ret) {
      return CK_NOT_FILE;
   }

   ret = krb5_kt_start_seq_get(context, kt, &cursor);
   if (ret) {
       return CK_NOT_VALID;
   }


   /* ---------------------------------------------------------------------- */
   /* Build the check mask  nd warning mask                                  */
   /* ---------------------------------------------------------------------- */
   cmask = 0;
   if((principal_filter == FILTER_USER) && (principal_action == ACTION_DENY)) cmask |= PRINCIPAL_MASK;
   if((principal_case_filter == FILTER_LOWER) && (principal_case_action == ACTION_DENY)) cmask |= LOWER_MASK;
   if((principal_case_filter == FILTER_UPPER) && (principal_case_action == ACTION_DENY)) cmask |= UPPER_MASK;
   if((strcmp(etype_filter, FILTER_EMPTY) != 0) && (etype_action == ACTION_DENY)) cmask |= ETYPE_MASK;
   if((strcmp(principal_domain_filter, FILTER_EMPTY) != 0) && (principal_domain_action == ACTION_DENY)) cmask |= DOMAIN_MASK;
   if(debug) fprintf(stderr, "%sDEBUG: Filter Mask: %d%s\n", debugColor, cmask, errResetColor);
   wmask = 0;
   if((principal_filter == FILTER_USER) && (principal_action == ACTION_WARNING)) wmask |= PRINCIPAL_MASK;
   if((principal_case_filter == FILTER_LOWER) && (principal_case_action == ACTION_WARNING)) wmask |= LOWER_MASK;
   if((principal_case_filter == FILTER_UPPER) && (principal_case_action == ACTION_WARNING)) wmask |= UPPER_MASK;
   if((strcmp(etype_filter, FILTER_EMPTY) != 0) && (etype_action == ACTION_WARNING)) wmask |= ETYPE_MASK;
   if((strcmp(principal_domain_filter, FILTER_EMPTY) != 0) && (principal_domain_action == ACTION_WARNING)) wmask |= DOMAIN_MASK;
   if(debug) fprintf(stderr, "%sDEBUG: Warning Mask: %d%s\n", debugColor, wmask, errResetColor);
   selected = -1;
   prevnbwarn = -1;

   /* ---------------------------------------------------------------------- */
   /* Loop on each keytab entry                                              */
   /* ---------------------------------------------------------------------- */
   while ((ret = krb5_kt_next_entry(context, kt, &entry, &cursor)) == 0) {
      ret = krb5_unparse_name(context, entry.principal, &pname);
      if (ret) {
         krb5_free_keytab_entry_contents(context, &entry);
         return CK_NOT_VALID;
      }
      /* ----------------------------------------------- */
      /* Get the username part from the principal string */
      /* ----------------------------------------------- */
      puser = strtok(pname, "@");
      if(puser == NULL) {
         krb5_free_unparsed_name(context, pname);
         krb5_free_keytab_entry_contents(context, &entry);
         return CK_NOT_VALID_PRINCIPAL;
      }
      /* ----------------------------------------------- */
      /* Get the domain part from the principal string   */
      /* ----------------------------------------------- */
      pdomain = strtok(NULL, "@");
      if(pdomain == NULL) {
         krb5_free_unparsed_name(context, pname);
         krb5_free_keytab_entry_contents(context, &entry);
         return CK_NOT_VALID_PRINCIPAL;
      }
      /* ----------------------------------------------- */
      /* Get the encryption cipher                        */
      /* ----------------------------------------------- */
      ename = buf;
      krb5_enctype_to_name(entry.key.enctype, FALSE, ename, sizeof(buf));

      /* ------------------------------------------------------------------------------------- */
      /* Check if the username match the username from the principal                           */
      /* Check if the username from the principal s upper case                                 */
      /* ------------------------------------------------------------------------------------- */
      strncpy(uname, puser, BUFSIZ);
      strncpy(lname, puser, BUFSIZ);
      s = uname ; while (*s) { *s = toupper((unsigned char) *s); s++; }
      s = lname ; while (*s) { *s = tolower((unsigned char) *s); s++; }
      id = 0;
      if(debug) fprintf(stderr, "%sDEBUG: Username: %s | Principal: %s | Domain: %s%s\n", debugColor, username, puser, pdomain, errResetColor);
      if (strcmp(lname, puser) == 0) id |= LOWER_MASK ;
      if (strcmp(uname, puser) == 0) id |= UPPER_MASK ;
      if (strcmp(lname, username) == 0) id |= PRINCIPAL_MASK;
      if(strcmp(etype_filter, FILTER_EMPTY) == 0) id |= ETYPE_MASK;
	 else if (strstr(etype_filter, ename) != NULL) id |= ETYPE_MASK;
      if (strcmp(principal_domain_filter, FILTER_EMPTY) == 0) id |= DOMAIN_MASK;
         else if (strstr(principal_domain_filter, pdomain) != NULL) id |= DOMAIN_MASK;
      if(debug) fprintf(stderr, "%sDEBUG: Entry id: %d%s\n", debugColor, id, errResetColor);

      if((id & cmask) == cmask) { 
         if(debug) fprintf(stderr, "%sDEBUG: Entry id match Filter Mask%s\n", debugColor, errResetColor);
	 nbwarn = count_set_bits(id & wmask);
	 if((prevnbwarn == -1) || (nbwarn < prevnbwarn)) {
            selected = id;
	    prevnbwarn = nbwarn;
	 }
      }

      if(debug) fprintf(stderr, "%sDEBUG: Select id: %d%s\n", debugColor, selected, errResetColor);
      krb5_free_unparsed_name(context, pname);
      krb5_free_keytab_entry_contents(context, &entry);
   }
   /* ---------------------------------------------------------------------- */
   /* End of the loop on each keytab entry                                   */
   /* ---------------------------------------------------------------------- */

   if (ret && ret != KRB5_KT_END) {
      return CK_NOT_VALID;
   }
   ret = krb5_kt_end_seq_get(context, kt, &cursor);
   if (ret) {
      return CK_NOT_VALID;
   }

   /* ------------------------------------------------------------------------- */
   /* Fail if no entry for the username                                         */
   /* ------------------------------------------------------------------------- */
   if(selected != -1) {
      if( !((selected & PRINCIPAL_MASK) == PRINCIPAL_MASK) & ((wmask & PRINCIPAL_MASK) == PRINCIPAL_MASK)) fprintf(stderr, "%sWARNING: no entry with expected principal%s\n", warnColor, errResetColor);
      if( !((selected & LOWER_MASK) == LOWER_MASK) & ((wmask & LOWER_MASK) == LOWER_MASK)) fprintf(stderr, "%sWARNING: principal name not lower case as expected%s\n", warnColor, errResetColor);
      if( !((selected & UPPER_MASK) == UPPER_MASK) & ((wmask & UPPER_MASK) == UPPER_MASK)) fprintf(stderr, "%sWARNING: principal name not upper case as expected%s\n", warnColor, errResetColor);
      if( !((selected & ETYPE_MASK) == ETYPE_MASK) & ((wmask & ETYPE_MASK) == ETYPE_MASK)) fprintf(stderr, "%sWARNING: no entry with expected encryption type%s\n", warnColor, errResetColor);
      if( !((selected & DOMAIN_MASK) == DOMAIN_MASK) & ((wmask & DOMAIN_MASK) == DOMAIN_MASK)) fprintf(stderr, "%sWARNING: no entry with expected domain%s\n", warnColor, errResetColor);
      return CK_OK;
   } else {
      fprintf(stderr, "%sERROR: no entry has been found with all expected criteria below%s\n", errorColor, errResetColor);
      if(cmask & PRINCIPAL_MASK) fprintf(stderr, "%s       - principal must match username%s\n", errorColor, errResetColor);
      if(cmask & LOWER_MASK) fprintf(stderr, "%s       - principal name must be lower case%s\n", errorColor, errResetColor);
      if(cmask & UPPER_MASK) fprintf(stderr, "%s       - principal name must be upper case%s\n", errorColor, errResetColor);
      if(cmask & ETYPE_MASK) fprintf(stderr, "%s       - encryption type must be one of %s%s\n", errorColor, etype_filter, errResetColor);
      if(cmask & DOMAIN_MASK) fprintf(stderr, "%s       - domain must be one of %s%s\n", errorColor, principal_domain_filter, errResetColor);
      return CK_KO;
   }
}

/*=========================================================
 * MAIN                             
 * ======================================================== */
int main(int argc, char **argv)
{
   char *source = NULL;
   char buffer[BUFSIZ] = { '\0' } ;
   size_t len = 0 ;
   size_t wlen = 0 ;
   size_t keytablen ;
   char *keytab;
   char *b64keytab;
   FILE* in ;
   FILE* out ;
   uid_t uid;
   gid_t gid;
   char uidString[256] ;
   size_t uidLen;
   size_t usernameLen;
   int eflag = 0;
   int c;
   struct stat st;
   char *cmdpath ;
   char *cmdname;
   int rc = 0;
   struct passwd *pw;
   char *username = NULL;

   FILE *conf;
   char *option = NULL;
   char *value = NULL;
   char *line = NULL;
   size_t pathLen = 0;
   ssize_t read;
   char *cursor;
   char *point;
   int uidOccurence = 0;
   int usernameOccurence = 0;
   char *keytab_destination ;
   char *tmp_destination ;
   int istty;

   /* ---------------------------------------------------
    * Extract the command name 
    * --------------------------------------------------- */
   cmdpath = malloc(strlen(argv[0]) + 1);
   strcpy(argv[0], cmdpath);
   cmdname = basename(cmdpath);
   /* ---------------------------------------------------
    * Define colors is output is a terminal
    * --------------------------------------------------- */
   istty = isatty(fileno(stderr));
   debugColor = istty ? DEBUG_COLOR : "";
   errorColor = istty ? ERROR_COLOR : "";
   warnColor = istty ? WARN_COLOR : "";
   errResetColor = istty ? NC : "";
   istty = isatty(fileno(stdout));
   infoColor = istty ? INFO_COLOR : "";
   outResetColor = istty ? NC : "";

   /* ---------------------------------------------------
    * Command Parameters Parsing
    * --------------------------------------------------- */
   while ((c = getopt (argc, argv, "dek:")) != -1)
      switch (c) {
         case 'd':
            debug = 1;
            break;
         case 'e':
            eflag = 1;
            break;
         case 'k':
            source = optarg;
            break;
         default:
            usage(argv[0]);
	    exit(-1);
      }
   if(source == NULL && eflag == 0) {
      usage(argv[0]);
      exit(-1);
   }
   if(source != NULL && eflag == 1) {
      usage(argv[0]);
      exit(-1);
   }

   /* -----------------------------------------------------
    * Get UID and GID of the current user and generate
    * the destination gssproxy user keytab path
    * ----------------------------------------------------- */
   uid = getuid();
   gid = getgid();
   pw = getpwuid (uid);
   if (pw) {
      username = pw->pw_name;
   } else {
      fprintf (stderr, "%sERROR: cannot find username for UID %u%s\n", errorColor, uid, errResetColor);
      exit(-1);
   }
   sprintf(uidString, "%d", uid);
   uidLen = strlen(uidString);
   usernameLen = strlen(username);

   /* ------------------------------------------------------
    *  It is time to become root to be able to read the
    *  configuration file
    *  ----------------------------------------------------- */
   seteuid(0);
   setegid(0);
   if(geteuid() != 0) {
      fprintf(stderr, "%sERROR: this utility is not correctly installed%s\n", errorColor, errResetColor);
      exit(-1);
   }
   /* ------------------------------------------------------
    * READ THE CONFIGURATION FILE /etc/install-keytab.conf
    * ------------------------------------------------------ */
   if(stat(CONF_FILE, &st)) {
      fprintf(stderr, "%sNo configuration file use default value%s\n", warnColor, errResetColor);
   } else {
      if((conf = fopen(CONF_FILE, "r" )) == NULL)
      {
	  fprintf(stderr, "%sERROR: cannot open configuration file:%s%s\n", errorColor, strerror(errno), errResetColor);
          exit(-1);
      } else {
         /* ------------------------------------------------------ */
         /* PARSE THE CONFIGURATION FILE                           */
         /* ------------------------------------------------------ */
         while ((read = getline(&line, &len, conf)) != -1) {
            line[strcspn(line, "\n")] = 0;
            if(line[0] == '#') continue;
            if(line[0] == '\0') continue;
            if(line[0] == '\t') continue;
            if(line[0] == ' ') continue;
            option = strtok(line, "=");
            if(option == NULL) {
               fprintf(stderr, "%sWARNING: %s bad option%s\n", warnColor, line, errResetColor);
            } else {
               value = strtok(NULL, "=");
               if(value == NULL) {
                  fprintf(stderr, "%sWARNING: %s bad option%s\n", warnColor, line, errResetColor);
               } else {
                  if (value[0] != '\n') {
                     /*========================================================================================*/
                      /* Option treatment  */
                     /*========================================================================================*/
                     if(strcmp(option, "etype_filter") == 0) {
                        if (strcmp(value, "all") == 0) {
                           etype_filter = FILTER_EMPTY;
                        } else {
                           etype_filter = malloc(strlen(value) + 1);
                           strcpy(etype_filter,value);
                        }
                     } else if (strcmp(option, "etype_action") == 0) {
                        if (strcmp(value, "allow") == 0) {
                           etype_action = ACTION_ALLOW;
                        } else if (strcmp(value, "deny") == 0) {
                           etype_action = ACTION_DENY;
                        } else if (strcmp(value, "warning") == 0) {
                           etype_action = ACTION_WARNING;
                        } else {
                           fprintf(stderr, "%sWARNING: %s bad value for option %s%s\n", warnColor, value, option, errResetColor);
                        }
                     } else if (strcmp(option, "principal_filter") == 0) {
                        if (strcmp(value, "all") == 0) {
                           principal_filter = FILTER_ALL;
                        } else if (strcmp(value, "user") == 0) {
                           principal_filter = FILTER_USER;
                        } else {
                           fprintf(stderr, "%sWARNING: %s bad value for option %s%s\n", warnColor, value, option, errResetColor);
                        }
                     } else if (strcmp(option, "principal_action") == 0) {
                        if (strcmp(value, "allow") == 0) {
                           principal_action = ACTION_ALLOW;
                        } else if (strcmp(value, "deny") == 0) {
                           principal_action = ACTION_DENY;
                        } else if (strcmp(value, "warning") == 0) {
                           principal_action = ACTION_WARNING;
                        } else {
                           fprintf(stderr, "%sWARNING: %s bad option value%s\n", warnColor, value, errResetColor);
                        }
                     } else if (strcmp(option, "principal_case_filter") == 0) {
                        if (strcmp(value, "all") == 0) {
                           principal_case_filter = FILTER_ALL;
                        } else if (strcmp(value, "upper") == 0) {
                           principal_case_filter = FILTER_UPPER;
                        } else if (strcmp(value, "lower") == 0) {
                           principal_case_filter = FILTER_LOWER;
                        } else {
                           fprintf(stderr, "%sWARNING: %s bad value for option %s%s\n", warnColor, value, option, errResetColor);
                        }
                     } else if (strcmp(option, "principal_case_action") == 0) {
                        if (strcmp(value, "allow") == 0) {
                           principal_case_action = ACTION_ALLOW;
                        } else if (strcmp(value, "deny") == 0) {
                           principal_case_action = ACTION_DENY;
                        } else if (strcmp(value, "warning") == 0) {
                           principal_case_action = ACTION_WARNING;
                        } else {
                           fprintf(stderr, "%sWARNING: %s bad option value%s\n", warnColor, value, errResetColor);
                        }
		     } else if(strcmp(option, "principal_domain_filter") == 0) {
                        if (strcmp(value, "all") == 0) {
                           principal_domain_filter = FILTER_EMPTY;
                        } else {
                           principal_domain_filter = malloc(strlen(value) + 1);
                           strcpy(principal_domain_filter,value);
                        }
                     } else if (strcmp(option, "principal_domain_action") == 0) {
                        if (strcmp(value, "allow") == 0) {
                           principal_domain_action = ACTION_ALLOW;
                        } else if (strcmp(value, "deny") == 0) {
                           principal_domain_action = ACTION_DENY;
                        } else if (strcmp(value, "warning") == 0) {
                           principal_domain_action = ACTION_WARNING;
                        } else {
                           fprintf(stderr, "%sWARNING: %s bad value for option %s%s\n", warnColor, value, option, errResetColor);
                        }
                     } else if (strcmp(option, "size_filter") == 0) {
                        if (strcmp(value, "all") == 0) {
                           size_filter = 0;
                        } else {
                                size_filter = atoi(value);
                                if(size_filter == 0)
                                   fprintf(stderr, "%sWARNING: %s bad value for option %s%s\n", warnColor, value, option, errResetColor);
                        }
                     } else if (strcmp(option, "size_action") == 0) {
                        if (strcmp(value, "allow") == 0) {
                           size_action = ACTION_ALLOW;
                        } else if (strcmp(value, "deny") == 0) {
                           size_action = ACTION_DENY;
                        } else if (strcmp(value, "warning") == 0) {
                           size_action = ACTION_WARNING;
                        } else {
                           fprintf(stderr, "%sWARNING: %s bad option value%s\n", warnColor, value, errResetColor);
                        }
                     } else if (strcmp(option, "destination_keytab") == 0) {
                        destination_keytab = malloc(strlen(value) + 1);
                        strcpy(destination_keytab,value);
                     } else if (strcmp(option, "source_keytab_protection") == 0) {
                        if (strcmp(value, "none") == 0) {
                           source_keytab_protection = ACTION_NONE;
                        } else if (strcmp(value, "permissions") == 0) {
                           source_keytab_protection = ACTION_PERMS;
                        } else if (strcmp(value, "remove") == 0) {
                           source_keytab_protection = ACTION_REMOVE;
                        } else {
                           fprintf(stderr, "%sWARNING: %s bad value for option %s%s\n", warnColor, value, option, errResetColor);
                        }
                     } else {
                        fprintf(stderr, "%sWARNING: %s unkown option%s\n", warnColor, option, errResetColor);
                     }

                  } else {
                     fprintf(stderr, "%sWARNING: %s bad option%s\n", warnColor, line, errResetColor);
                  }
               }
            }
         }
         fclose(conf);
         if (line) free(line);
         /* ------------------------------------------------------ */
      }
   }

   if(debug) fprintf(stderr, "%sDEBUG: etype_filter = %s  (%s)%s\n", debugColor, etype_filter, DEFAULT_ETYPE_FILTER, errResetColor) ;
   if(debug) fprintf(stderr, "%sDEBUG: etype_action = %d  (%d)%s\n", debugColor, etype_action, DEFAULT_ETYPE_ACTION, errResetColor) ;
   if(debug) fprintf(stderr, "%sDEBUG: principal_filter = %d  (%d)%s\n", debugColor, principal_filter, DEFAULT_PRINCIPAL_FILTER, errResetColor);
   if(debug) fprintf(stderr, "%sDEBUG: principal_action = %d  (%d)%s\n", debugColor, principal_action, DEFAULT_PRINCIPAL_ACTION, errResetColor);
   if(debug) fprintf(stderr, "%sDEBUG: principal_case_filter = %d  (%d)%s\n", debugColor, principal_case_filter, DEFAULT_PRINCIPAL_CASE_FILTER, errResetColor);
   if(debug) fprintf(stderr, "%sDEBUG: principal_case_action = %d  (%d)%s\n", debugColor, principal_case_action, DEFAULT_PRINCIPAL_CASE_ACTION, errResetColor);
   if(debug) fprintf(stderr, "%sDEBUG: principal_domain_filter = %s  (%s)%s\n", debugColor, principal_domain_filter, DEFAULT_PRINCIPAL_DOMAIN_FILTER, errResetColor);
   if(debug) fprintf(stderr, "%sDEBUG: principal_domain_action = %d  (%d)%s\n", debugColor, principal_domain_action, DEFAULT_PRINCIPAL_DOMAIN_ACTION, errResetColor);
   if(debug) fprintf(stderr, "%sDEBUG: size_filter = %d  (%d)%s\n", debugColor, size_filter, DEFAULT_SIZE_FILTER, errResetColor);
   if(debug) fprintf(stderr, "%sDEBUG: size_action = %d  (%d)%s\n", debugColor, size_action, DEFAULT_SIZE_ACTION, errResetColor);
   if(debug) fprintf(stderr, "%sDEBUG: source_keytab_protection = %d  (%d)%s\n", debugColor, source_keytab_protection, DEFAULT_SOURCE_KEYTAB_PROTECTION, errResetColor);

   /* ============================================================================ */
   /* Expand the destination_keytab file full path name                            */
   /* ============================================================================ */
   cursor = destination_keytab;
   while ((point = strchr(cursor, '%')) != NULL) {
      if(point[1] == 'U')  uidOccurence++ ;
      if(point[1] == 'u') usernameOccurence++ ;
      cursor = &point[1];
   }

   sprintf(uidString, "%d", uid);
   uidLen = strlen(uidString);
   usernameLen = strlen(username);
   pathLen = strlen(destination_keytab);
   pathLen = pathLen - 2 * (uidOccurence + usernameOccurence) + uidOccurence * uidLen + usernameOccurence * usernameLen ;
   keytab_destination = malloc(pathLen + 1);
   tmp_destination = malloc(pathLen + 4 + 1);
   keytab_destination[0] = '\0';
   tmp_destination[0] = '\0';

   cursor = destination_keytab;
   while ((point = strchr(cursor, '%')) != NULL) {
      if(point[1] == 'U')  {
         point[0] = '\0';
         point[1] = '\0';
         strcat(keytab_destination, cursor);
         strcat(keytab_destination, uidString);
         cursor = &(point[2]);
      } else if(point[1] == 'u') {
         point[0] = '\0';
         point[1] = '\0';
         strcat(keytab_destination, cursor);
         strcat(keytab_destination, username);
         cursor = &(point[2]);
      } else {
         point[0] = '\0';
         strcat(keytab_destination, cursor);
         strcat(keytab_destination, "%");
         cursor = &(point[1]);
      }
   }
   strcat(keytab_destination, cursor);
   strcat(tmp_destination, keytab_destination);
   strcat(tmp_destination, ".tmp");
   if(debug) fprintf(stderr, "%sDEBUG: keytab_destination = %s%s\n", debugColor, keytab_destination, errResetColor);
   if(keytab_destination[0] != '/') {
      fprintf(stderr, "ERROR: defined destination path is not an absolute path\n");
      exit(-1);
   }
   /* ----------------------------------------------------------------- */

   /* -----------------------------------------------------------
    * Enable syslog
    * ----------------------------------------------------------- */
   setlogmask(LOG_UPTO(LOG_NOTICE));
   openlog(cmdname, LOG_PID | LOG_NDELAY, LOG_AUTH);

   /* ----------------------------------------------------------------- 
    * Build file and check size                                         
    * Open the source keytab owned by the user for read (option -k)
    * Or decode the keytab stored in environment variable (option -e)
    * ----------------------------------------------------------------- */
   /* ------------------------------------------------------
    * Set the umask to create new file with r-------- perms
    * ------------------------------------------------------ */
   umask(S_IROTH|S_IWOTH|S_IRGRP|S_IWGRP|S_IWUSR);
   /* ---------------------------------------------------------
    * Open the destination keytab owned by root for write
    * --------------------------------------------------------- */
   out = fopen(tmp_destination, "wb" ) ;
   if(out == NULL)
   {
       if(debug) fprintf(stderr, "%sDEBUG: cannot open %s for write%s\n", debugColor, tmp_destination, errResetColor);
       fprintf(stderr, "%sERROR: cannot open destination file:%s%s\n", errorColor, strerror(errno), errResetColor);
       exit(-1);
   }
   /* -----------------------------------------------------------
    * Force owner/group and permissions of the destination
    * to be sure that all is as expected
    * ----------------------------------------------------------- */
   chmod(tmp_destination, S_IRUSR);
   chown(tmp_destination, 0, 0);

   if(eflag == 0) {
      /* -----------------------*/
      /* CASE: option -k keytab */
      /* -----------------------*/
      /* ----------------------------------------------------------------- */
      /* Switch as the user to check the keytab validity                   */
      /* ----------------------------------------------------------------- */
      setegid(gid);
      seteuid(uid);
      stat(source, &st);
      if((st.st_size > size_filter) && (size_filter != 0)) {
         if(size_action == ACTION_WARNING) {
            fprintf(stderr, "WARNING: keytab file size does not expect the size threshold (%d)\n", size_filter);
         } else if(size_action == ACTION_DENY) {
            fprintf(stderr, "ERROR: keytab file size is too big (%d)\n", size_filter);
            setegid(0);
            seteuid(0);
            if(remove(tmp_destination) == -1)
               fprintf(stderr, "%sERROR: cannot remove temporary file:%s%s\n", errorColor, strerror(errno), errResetColor);
            exit(-1);
         }
      }
      in = fopen(source, "rb" ) ;
      if(in == NULL)
      {
          fprintf(stderr, "%sERROR: cannot open source file:%s%s\n", errorColor, strerror(errno), errResetColor);
          setegid(0);
          seteuid(0);
          if(remove(tmp_destination) == -1)
             fprintf(stderr, "%sERROR: cannot remove temporary file:%s%s\n", errorColor, strerror(errno), errResetColor);
          exit(-1);
      }
      do
      {
         len = fread(buffer, 1, BUFSIZ, in); 
         if(len == 0 && ferror(in) != 0) {
            fprintf(stderr, "%sERROR: cannot read keytab file:%s%s\n", errorColor, strerror(errno), errResetColor);
            fclose(in);
            setegid(0);
            seteuid(0);
            fclose(out) ;
            if(remove(tmp_destination) == -1)
               fprintf(stderr, "%sERROR: cannot remove temporary file:%s%s\n", errorColor, strerror(errno), errResetColor);
            syslog(LOG_ERR, "fail to install user keytab for uid %d", uid);
            closelog();
	    exit(-1);
         }
         if (len > 0) {
            setegid(0);
            seteuid(0);
            wlen = fwrite(buffer, 1, len, out);
            setegid(uid);
            seteuid(gid);
            if(wlen != len) {
               fprintf(stderr, "%sERROR: cannot write keytab file:%s%s\n", errorColor, strerror(errno), errResetColor);
               fclose(in);
               setegid(0);
               seteuid(0);
               fclose(out) ;
               if(remove(tmp_destination) == -1)
                  fprintf(stderr, "%sERROR: cannot remove temporary file:%s%s\n", errorColor, strerror(errno), errResetColor);
               syslog(LOG_ERR, "fail to install user keytab for uid %d", uid);
               closelog();
	       exit(-1);
            }
	 }
      } while (len > 0);
      fclose(in);
      setegid(0);
      seteuid(0);
   } else {
      /* -----------------------*/
      /* CASE: option -e        */
      /* -----------------------*/
      b64keytab = getenv(KEYTABENV);
      if(b64keytab == NULL) {
         fprintf(stderr, "%sERROR: cannot use option -e for interactive usage%s\n", errorColor, errResetColor);
         if(remove(tmp_destination) == -1)
            fprintf(stderr, "%sERROR: cannot remove temporary file:%s%s\n", errorColor, strerror(errno), errResetColor);
         exit(-1);
      }
      keytablen = b64_decoded_size(b64keytab);
      if((keytablen > size_filter) && (size_filter != 0)) {
         if(size_action == ACTION_WARNING) {
            fprintf(stderr, "%sWARNING: keytab file size does not expect the size threshold (%d)%s\n", warnColor, size_filter, errResetColor);
         } else if(size_action == ACTION_DENY) {
            fprintf(stderr, "%sERROR: keytab file size is too big (%d)%s\n", errorColor, size_filter, errResetColor);
            if(remove(tmp_destination) == -1)
               fprintf(stderr, "%sERROR: cannot remove temporary file:%s%s\n", errorColor, strerror(errno), errResetColor);
            exit(-1);
         }
      }
      keytab = malloc(keytablen);

      if (!b64_decode(b64keytab, (unsigned char *)keytab, keytablen)) {
         fprintf(stderr, "%sERROR: decode failure%s\n", errorColor, errResetColor);
         fclose(out) ;
         if(remove(tmp_destination) == -1)
            fprintf(stderr, "%sERROR: cannot remove temporary file:%s%s\n", errorColor, strerror(errno), errResetColor);
         exit(-1);
      }
      wlen = fwrite(keytab, 1, keytablen, out);
      if(wlen != keytablen) {
         fprintf(stderr, "%sERROR: cannot write keytab file:%s%s\n", errorColor, strerror(errno), errResetColor);
         fclose(out) ;
         if(remove(tmp_destination) == -1)
            fprintf(stderr, "%sERROR: cannot remove temporary file:%s%s\n", errorColor, strerror(errno), errResetColor);
         syslog(LOG_ERR, "fail to install user keytab for uid %d", uid);
         closelog();
         exit(-1);
      }
   }
   fclose(out) ;
   /* ----------------------------------------------------------------- */
    
   /* --------------------------------------------------------------
    * Check if the keytab is valid
    * Check if the username match the username from the principal 
    * Check if the username from the principal s upper case 
    * Check if the cipher is strong (aes256)
    * --------------------------------------------------------------*/
   rc = check_keytab(tmp_destination, username);
   switch(rc) {
           case CK_OK:
              break;
           case CK_KO:
              fprintf(stderr, "%sERROR: no expected keytab entry found%s\n", errorColor, errResetColor);
              if(remove(tmp_destination) == -1)
                 fprintf(stderr, "%sERROR: cannot remove temporary file:%s%s\n", errorColor, strerror(errno), errResetColor);
              syslog(LOG_ERR, "user keytab installation failed for user %d", uid);
              closelog();
              exit(CK_KO);
              break;
           case CK_NOT_VALID_PRINCIPAL:
              fprintf(stderr, "%sERROR: no valid principal in the keytab%s\n", errorColor, errResetColor);
              if(remove(tmp_destination) == -1)
                 fprintf(stderr, "%sERROR: cannot remove temporary file:%s%s\n", errorColor, strerror(errno), errResetColor);
              syslog(LOG_ERR, "user keytab installation failed for user %d", uid);
              closelog();
              exit(CK_NOT_VALID_PRINCIPAL);
              break;
           case CK_NOT_VALID:
              fprintf(stderr, "%sERROR: invalid keytab%s\n", errorColor, errResetColor);
              if(remove(tmp_destination) == -1)
                 fprintf(stderr, "%sERROR: cannot remove temporary file:%s%s\n", errorColor, strerror(errno), errResetColor);
              syslog(LOG_ERR, "user keytab installation failed for user %d", uid);
              closelog();
              exit(CK_NOT_VALID);
              break;
           case CK_NOT_FILE:
              fprintf(stderr, "%sERROR: not a file%s\n", errorColor, errResetColor);
              if(remove(tmp_destination) == -1)
                 fprintf(stderr, "%sERROR: cannot remove temporary file:%s%s\n", errorColor, strerror(errno), errResetColor);
              syslog(LOG_ERR, "user keytab installation failed for user %d", uid);
              closelog();
              exit(CK_NOT_FILE);
              break;
           case CK_NO_FILE:
              fprintf(stderr, "%sERROR: no file provided%s\n", errorColor, errResetColor);
              if(remove(tmp_destination) == -1)
                 fprintf(stderr, "%sERROR: cannot remove temporary file:%s%s\n", errorColor, strerror(errno), errResetColor);
              syslog(LOG_ERR, "user keytab installation failed for user %d", uid);
              closelog();
              exit(CK_NO_FILE);
              break;
           case CK_ERR_CONTEXT:
              fprintf(stderr, "%sERROR: internal error%s\n", errorColor, errResetColor);
              if(remove(tmp_destination) == -1)
                 fprintf(stderr, "%sERROR: cannot remove temporary file:%s%s\n", errorColor, strerror(errno), errResetColor);
              syslog(LOG_ERR, "user keytab installation failed for user %d", uid);
              closelog();
              exit(CK_ERR_CONTEXT);
              break;
   }

   /* -----------------------------------------------------------
    * Open the destination keytab owned by root for write
    * Force owner/group and permissions of the destination
    * to be sure that all is as expected
    * ----------------------------------------------------------- */

   if(rename(tmp_destination, keytab_destination) == 0) {
      chown(keytab_destination, 0, 0);
      chmod(keytab_destination, S_IRUSR);
      fprintf(stdout, "%sINFO: keytab successfully installed%s\n", infoColor, outResetColor);
      syslog(LOG_NOTICE, "user keytab installation for user %d", uid);
   } else {
      fprintf(stderr, "%sERROR: cannot write keytab file:%s%s\n", errorColor, strerror(errno), errResetColor);
      syslog(LOG_ERR, "user keytab installation failed for user %d", uid);
      if(remove(tmp_destination) == -1)
      {
         fprintf(stderr, "%sERROR: cannot remove temporary file:%s%s\n", errorColor, strerror(errno), errResetColor);
         syslog(LOG_ERR, "fail to cleanup temporary file for user %d", uid);
      }
      closelog();
      exit(-1);
   }


   /* ---------------------------------------------------------------
    * Switch back to the original user and protect the source file
    * --------------------------------------------------------------- */
   setegid(gid);
   seteuid(uid);
   if(eflag == 0) {
      /* -----------------------*/
      /* CASE: option -k keytab */
      /* -----------------------*/
      if(source_keytab_protection == ACTION_PERMS) {
         if(chmod(source, S_IRUSR|S_IWUSR) == -1)
         {
            fprintf(stderr, "%sERROR: cannot protect source file:%s%s\n", errorColor, strerror(errno), errResetColor);
            syslog(LOG_ERR, "fail to protect source keytab for uid %d", uid);
            closelog();
            exit(-1);
         }
      } else if(source_keytab_protection == ACTION_REMOVE) {
         if(remove(source) == -1)
         {
            fprintf(stderr, "%sERROR: cannot protect source file:%s%s\n", errorColor, strerror(errno), errResetColor);
            syslog(LOG_ERR, "fail to protect source keytab for uid %d", uid);
            closelog();
            exit(-1);
         }
      }
   }
   closelog();
   exit(0);
}

