INSTALL-KEYTAB
==============

NAME 
----

install-keytab - Allow a non-root user to copy its *keytab* in a
protected keytab folder only accessible by root (such as the *gssproxy*
client keytab folder).

SYNOPSIS 
--------

**install-keytab** -e | -k &lt;file&gt;

DESCRIPTION
-----------

Copy an given *keytab* file in a protected keytab folder

The behavior of **install-keytab** can be defined through the
**install-keytab.conf(5)** configuration file.

The destination keytab folder and destination keytab file are defined by
the *destination\_keytab* configuration parameter (default is
**/var/lib/gssproxy/clients/%U.keytab** ). This default value
corresponds to the default *client\_keytab* parameter of the *gssproxy*
( **cred\_store=client\_keytab:/var/lib/gssproxy/clients/%U.keytab** ).

Depending of the *source\_keytab\_protection* configuration parameter,
the given keytab file is impacted

- its permissions can be forced to read-write only for the owner
- it can be deleted after its installation in the destination folder

OPTIONS
-------

**-k &lt;file&gt;**

Specify the *keytab* file to be copied in the destination keytab folder.

**-e**

The *keytab* is provided through an environment variable. This could be useful for integration with other tool such as **push-keytab(1)** utility

DEPENDENCIES
------------

- This executable must be *owned by root* and must have the *setuid* bit enabled.
- This executable need *libkrb5* and *libk5crypto* dynamic libraries.

EXAMPLES
--------

**% install-keytab -k my.keytab**

Install the my.keytab file to the right protected destination folder.

SEE ALSO 
--------

**install-keytab.conf(5)** , **push-keytab(1)**

LICENSE
-------

GNU General Public License version 3

AUTHOR
------

Christian Gajan

------------------------------------------------------------------------


INSTALL-KEYTAB.CONF
===================

NAME 
----

install-keytab.conf - Configuration file of the **install-keytab(1)** utility

DESCRIPTION 
-----------

**install-keytab(1)** obtains configuration from the **/etc/install-keytab.conf** file. The file contains keyword-value pairs, one per line. A keyword and its 
value are separed by one ’=’ character (e.g. etype\_filter=all). Lines starting with '\#' and empty lines are interpreted as comments.

The possible keywords and their meanings are as follows (note that keywords and value are case-sensitive): 

### etype\_filter

control encryption types accepted from keytab

- **all** : means all encryption types are accepted
- **a commas separed list** of encryption type (e.g. aes256-cts-hmac-sha1-96,aes128-cts-hmac-sha1-96)
- default value is **aes256-cts-hmac-sha1-96**

### etype\_action

control the behavor relative to encryption type

- **allow**: all encryption types are accepted
- **warning**: get a warning if no keytab entries with specified encryption type is found
- **deny**: reject keytab if no keytab entries with specified encryption type is found
- default is **deny**

### principal\_filter

control how principal names are accepted from keytab

- **all**: means all principal names are accepted
- **user**: means only principal equals to username
- default value is **user**

### principal\_action

control the behavor relative to principal name

- **allow**: all principal names are accepted
- **warning**: get a warning if no keytab entries with specified principal name is found
- **deny**: reject keytab if no keytab entries with specified principal name is found
- default is **deny**

### principal\_case\_filter

control how character cases of principal names are accepted from keytab

- **all**: means all character cases are accepted
- **upper**: means only upper case
- **lower**: means only lower case
- default value is **all**

### principal\_case\_action

control the behavor relative to character case of principal name

- **allow**: all character cases are accepted
- **warning**: get a warning if no keytab entries with specified character case is found
- **deny**: reject keytab if no keytab entries with specified character case is found
- default is **allow**

### principal\_domain\_filter

control how principal’s domains are accepted from keytab

- **all**: means all domains are accepted
- **a commas separed list** of domains (e.g. FR.COMPANY.COM,ES.COMPANY.COM)
- default value is **all**

### principal\_domain\_action

control the behavor relative to domain of principal

- **allow**: all domains are accepted
- **warning**: get a warning if no keytab entries with specified domains is found
- **deny**: reject keytab if no keytab entries with specified domains is found
- default is **allow**

### destination\_keytab

define the full path of the destination keytab. This full path string may contain substitution patterns. The supported patterns are:

- **%U** substitutes to the user’s numeric uid (e.g. 1234)
- **%u** substitutes to the user’s username (e.g. john)
- default value is **/var/lib/gssproxy/users/%U.keytab**

### size\_filter

control how keytab sizes are accepted

- **all**: any keytab size is accepted
- ***&lt;number&gt;***: size in byte
- default value is **4096**

### size\_action

control the behavor relative to the size of the keytab

- **allow**: all sizes are accepted
- **warning**: get a warning if keytab size if bigger than the specified size
- **deny**: reject keytab if keytab size if bigger than the specified size
- default is **deny**

### source\_keytab\_protection

control how given source keytab file is protected

- **none**: the source keytab remains unchanged
- **permissions**: the source keytab permissions is forced to only read-write for owner
- **remove**: the source keytab is deleted after been copied in the destination folder
- default value is **permissions**

SEE ALSO
--------

**install-keytab(1)**

LICENSE 
-------

GNU General Public License version 3

AUTHOR
------

Christian Gajan

------------------------------------------------------------------------

PUSH-KEYTAB
===========

NAME 
----

push-keytab - push an user’s *keytab* to a secure keytab folder of a remote server

SYNOPSIS
--------

**push-keytab** -k &lt;file&gt; -h &lt;host&gt; \[-p &lt;port&gt;\]

DESCRIPTION
-----------

Push the user’s *keytab* file **&lt;file&gt;** to a keytab folder of the remote server **&lt;host&gt;** without compromise the keytab security. 
The exact destination location of the pushed keytab on the remote server depend on the configuration of the **install-keytab** utility installed on the remote server. 
See **install-keytab(1)** and **install-keytab.conf(5)**

OPTIONS
-------

**-k &lt;file&gt;**

Specify the *keytab* file to be copied to the keytab folder on the remote server.

**-h &lt;host&gt;**

Specify the remote **host** on which the keytab must be deployed. The host must have the **install-keytab(1)** utility installed as **/usr/bin/install-keytab**

**-p &lt;port&gt;**

The TCP **port** number of the remote SSH service.

### NOTES

This program use the *SSH* service of the remote host to remotely launch the **install-keytab** utility which must be available on the remote server.

DEPENDENCIES 
------------

- This executable need *libssh* dynamic library.
- On the remote server the **install-keytab** utility must be available as **/usr/bin/install-keytab**

EXAMPLES
--------

**% push-keytab -k my.keytab -h theserver**

Install the my.keytab file to the keytab folder on the remote server theserver.

SEE ALSO
--------

**install-keytab(1)**, **install-keytab.conf(5)**

LICENSE
-------

GNU General Public License version 3

AUTHOR 
------

Christian Gajan

------------------------------------------------------------------------

