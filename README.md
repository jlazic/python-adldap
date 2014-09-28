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
ad.connect('ldaps://192.168.1.166', 'administrator@lazic.local', 'Password01')
```

LDAP host must have scheme (ldap or ldaps), depending are you connecting via SSL, or not. If your LDAP uses standard ports, you dont need to enter port.
Username should have UPN suffix, I have found that connecting via python-ldap with username that have dot fails if username is provided without UPN suffix. ie. username 'josip.lazic' fails, while 'josip.lazic@domain.local' works.

###Users

Assuming that you have conencted to LDAP you can find user by name/username

```python
In  [8]: user = ad.get_user_by_name('josip.lazic')
Out [8]: User: Josip Lazic

```

or by DN


```python
In [9]: user = ad.get_user_by_dn('CN=Josip Lazic,OU=Korisnici,DC=lazic,DC=local')
Out[9]: User: Josip Lazic

```

Raw object properties are contained in self.properties dict.

```python
In [10]: user.properties['pwdLastSet']
Out[10]: ['130563651936689576']

```

Some properties are added to class for easier accessing like disabled, locked_out, modified_time, display_name,...
All of them are in listed in html documentation.

```python
In [11]: user.disabled
Out[11]: False

In [12]: user.modified_time
Out[12]: 1411887993.0

In [13]: user.display_name
Out[13]: 'Josip Lazic'

In [14]: user.distinguished_name
Out[14]: 'CN=Josip Lazic,OU=Zagreb,OU=Home,DC=lazic,DC=local'

```

User properties can be changed 

```python
In [16]: user.properties['givenName']
Out[16]: ['Josip']

In [23]: user.properties['givenName'] = 'Joseph'

In [24]: user.set_properties()
Out[24]: True

In [26]: user.refresh()

In [27]: user.properties['givenName']
Out[27]: ['Joseph']

```

List of object properties that are retrieved are in constants.py, for user that would be list
MANDATORY_PROPS_USER. If needed you can add items to that list, like employeeID, or mobile.

```python
In [44]: from ad_ldap.constants import *
In [45]: MANDATORY_PROPS_USER
Out[45]: 
('distinguishedName',
 'objectClass',
 'objectCategory',
 'name',
 'description',
 'createTimeStamp',
 'modifyTimeStamp',
 'sAMAccountName',
 'msDS-User-Account-Control-Computed',
 'memberOf')
 
```

For items not by default in MANDATORY_PROPS_USER, you can retrieve them using get_properties method

```python
In [39]: user.get_properties(['mobile', 'employeeID', 'employeeNumber', 'employeeType'])

In [40]: user.properties['mobile']
Out[40]: ['0123456789']

In [41]: user.properties['employeeID']
Out[41]: ['EID-789']

In [42]: user.properties['employeeNumber']
Out[42]: ['42']

In [43]: user.properties['employeeType']
Out[43]: ['Will work for food']

```

Once retrieved properties can be changed, and saved back to LDAP

```python
In [46]: user.properties['employeeType'] = 'Will work for money'

In [47]: user.set_properties()
Out[47]: True

In [48]: user.refresh()

In [49]: user.properties['employeeType']
Out[49]: ['Will work for money']

```


###Groups

Find group by name

```python

```


Similar to searching users you can search for Computer, Group, Container, or generic AD object using these functions

```python
ad.get_computer_by_dn
ad.get_computer_by_name
ad.get_group_by_dn
ad.get_group_by_name
ad.get_user_by_dn
ad.get_user_by_name
ad.get_object_by_dn
ad.get_object_by_name
ad.get_container_by_dn
```

```python

```






```python

```