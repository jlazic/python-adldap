python-adldap
=============

This module is designed to use the existing python-ldap module to bind to AD and create objects that can be used to manipulate Active Directory objects. New classes provide utility methods for common actions, like enabling or disabling accounts, or editing group memberships.

This is fork from py-ad-ldap repository on Google Code: https://code.google.com/p/py-ad-ldap/

Documentation can be found in apidocs directory. I have provided some examples, but reading source code will provide you with most this you need to know.

### Requirements
python-ldap =< 2.4

## Examples

### Connecting

```python
from ad_ldap.ad_ldap import Domain
ad = Domain()
ad.connect('ldaps://192.168.1.166', 'administrator@lazic.local', 'Password01')
```

LDAP host must have scheme (ldap or ldaps), depending are you connecting via SSL, or not. If your LDAP uses standard ports, you dont need to enter port.
Username should have UPN suffix, I have found that connecting via python-ldap with username that have dot fails if username is provided without UPN suffix. ie. username 'josip.lazic' fails, while 'josip.lazic@domain.local' works.

### Users

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

As you can guess from the name, methods enable and disable will enable and disable User

```python
In [24]: user = ad.get_user_by_name('py.user')

In [25]: user.disabled
Out[25]: False

In [26]: user.disable()
Out[26]: True

In [27]: user.disabled
Out[27]: True

In [28]: user.enable()
Out[28]: True

In [29]: user.disabled
Out[29]: False
```

### Password change

There are 2 ways to change user password. Selfchange, and administrative change. In first case you must supply both old user password, and new password. During this user that you used for connecting to LDAP/AD does not need to have privilege to change other users password.

```python
In [5]: user = ad.get_user_by_name('deda.milan')

In [7]: user.change_password(oldpassword='Password01', newpassword='SuperSecret961') 
Out[7]: True

```

If you pass wrong old password, InvalidCredentials exception will be raised

```python
In [15]: user.change_password(oldpassword='WrongOldPass', newpassword='SuperS.90')
    920                 # Incorrect current password.
--> 921                 raise errors.InvalidCredentials(message)
InvalidCredentials: LDAP Error. desc: Constraint violation info: 00000056: AtrErr: DSID-03191083, #1:
	0: 00000056: DSID-03191083, problem 1005 (CONSTRAINT_ATT_TYPE), data 0, Att 9005a (unicodePwd)

```

Also, new password must be aligned with your domain password policy, so giving weak new password will result in raising DoesNotMeetPasswordPolicy exception

```python
In [16]: user.change_password(oldpassword='Password01', newpassword='weakpass')
    923                 #Does not meet password policy
--> 924                 raise errors.DoesNotMeetPasswordPolicy(message)

DoesNotMeetPasswordPolicy: LDAP Error. desc: Constraint violation info: 0000052D: AtrErr: DSID-03191083, #1:
	0: 0000052D: DSID-03191083, problem 1005 (CONSTRAINT_ATT_TYPE), data 0, Att 9005a (unicodePwd)
	
```

If you connect to domain with administrative user that has privilege to change other users passwords, you do not need to supply old password

```python
In [17]: user.change_password(oldpassword=None, newpassword='Password99')
Out[17]: True
```

When changing user password this way, all the same password policies apply, except password history policy.

### Groups

Find group by name

```python
In [5]: ham = ad.get_group_by_name('Ham')

In [6]: ham
Out[6]: Group: Ham

In [7]: ham.distinguished_name
Out[7]: 'CN=Ham,CN=Users,DC=lazic,DC=local'

```

Similar to User object, Group object have its properties, but unlike user group can have members
You can add members to group. Group can have another group, user, or computer as its member.

```python
In [8]: ham.get_members()
Out[8]: [Computer: PC1, Group: Baz, User: Nataša Moskva, User: Lilika]

```

Add member to a group

```python
In [5]: group = ad.get_group_by_name('Spam')

In [6]: user = ad.get_user_by_name('zika.pavlovic')

In [7]: group.get_members()
Out[7]: []

In [8]: group.add_member(user)
Out[8]: True

In [9]: group.get_members()
Out[9]: [User: Žika Pavlović]
```

You can add multiple members to group in one go

```python
In [14]: group = ad.get_group_by_name('eggs')

In [16]: group.get_members()
Out[16]: []

In [17]: pc = ad.get_computer_by_name('pc1')

In [18]: spam = ad.get_group_by_name('spam')

In [19]: user = ad.get_user_by_name('misa.pavlovic')

In [20]: group.add_members([pc, user, spam])
Out[20]: True

In [21]: group.get_members()
Out[21]: [Computer: PC1, User: Miša Pavlović, Group: Spam]
```

If user already is member of a group MemberExists exception will be raised

```python
In [11]: user
Out[11]: User: Žika Pavlović

In [12]: group.get_members()
Out[12]: [User: Žika Pavlović]

In [13]: group.add_member(user)
---------------------------------------------------------------------------
   1103 
   1104         if member.distinguished_name in self.properties['member']:
-> 1105             raise errors.MemberExist
   1106 
   1107         self.properties['member'].append(member.distinguished_name)
MemberExist: 
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


## Similar projects
List of similar projects that you might find interesting

https://github.com/dfwarden/ActiveDirectory-Python

http://bazaar.launchpad.net/~csawyer-yumaed/adpasswd/trunk/view/head:/adpasswd.py

https://github.com/geertj/python-ad
