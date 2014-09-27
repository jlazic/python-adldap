python-adldap
=============

This module is designed to use the existing python-ldap module to bind to AD and create objects that can be used to manipulate Active Directory objects. New classes provide utility methods for common actions, like enabling or disabling accounts, or editing group memberships.

This is fork from py-ad-ldap repository on Google Code: https://code.google.com/p/py-ad-ldap/

### Requirements
python-ldap =< 2.4

##Examples

###Connecting

```python
from ad_ldap.ad_ldap import Domain
ad = Domain()
ad.connect('ldaps://10.10.10.10', 'username@domain.local', 'password')
```

LDAP host must have scheme (ldap or ldaps), depending are you connecting via SSL, or not. If your LDAP uses standard ports, you dont need to enter port.
Username should have UPN suffix, I have found that connecting via python-ldap with username that have dot fails if username is provided without UPN suffix. ie. username 'josip.lazic' fails, while 'josip.lazic@domain.local' works.

###Searching

Assuming that you have conencted to LDAP

```python
user = ad.

```




```python

```