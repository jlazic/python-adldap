#!/usr/bin/python
"""A module for using ldap to manipulate objects in AD.

This module creates two basic object classes: Domain, and ADObject.

The Domain class is used for every interaction with the Active Directory
service itself, such as creating, modifying, or searching for objects.

The ADObject class represents an object in the directory.  It could be a user,
computer, OU, or any object.  It has an attribute called 'properties' that is a
dict of the properties of the object.  To modify a property, you change it in
the dict and call set_properties().  Every ADObject has a '_domain_obj' property
that is a link to the Domain object, which will do the actual modifications to
the directory.

User, Computer, Group, and Container all inherit from ADObject, and add some
attributes and methods for convenience.  For example, the User object has
disable() and enable() methods for disabling and enabling user accounts, and a
'disabled' property to make it easier to tell if an object has been disabled.


Copyright 2010 Google Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import copy
import re
import time

import constants
import errors
import ldap
import ldap.controls
import ldap.filter
import ldap.modlist


def ad_time_to_unix(ad_time):
    """Converts AD double-wide int format to seconds since the epoch format.

    Args:
      ad_time: a 64-bit integer time format used by AD with the number of 100ns
               intervals since January 1, 1601.

    Note: cribbed from filetimes.py at http://reliablybroken.com/b/2009/09/

    Returns:
      An int with the number of seconds since January 1, 1970.
    """
    return int((ad_time - constants.EPOCH_AS_FILETIME) / 10000000)


def text_time_to_unix(text_time):
    """Converts alternate time format text strings to seconds since the epoch.

    Some Active Directory properties are stored in a YYYYMMDDHHMMSS.0Z format.
    See http://msdn.microsoft.com/en-us/library/aa772189(VS.85).aspx for details.

    Args:
      text_time: the string containing the time value.

    Returns:
      The number of seconds since the epoch.
    """
    groups = constants.RE_TEXT_TIME.findall(text_time)
    time_tuple = tuple([int(x) for x in groups[0] + (0, 0, 0)])
    return time.mktime(time_tuple)


def bitmask_bool(bitmask, value):
    """Returns True or False depending on whether a particular bit has been set.

    Microsoft uses bitmasks as a compact way of denoting a number of boolean
    settings.  The second bit, for example, might be the ADS_UF_ACCOUNTDISABLE
    bit, so if the second bit is a 1, then the account is disabled, and if it is
    a 0, then it is not.

    As an example, to create the 'disabled' property of a User object, we use the
    userAccountControl property and ADS_UF_ACCOUNTDISABLE constant.

    bitmask_bool(user.user_account_control, constants.ADS_UF_ACCOUNTDISABLE)
    This will return True if the bit is set in user.user_account_control.

    Args:
      bitmask: a number representing a bitmask
      value:  the value to be checked (usually a known constant)

    Returns:
      True if the bit has been set, False if it has not.
    """
    if int(bitmask) & int(value):
        return True
    else:
        return False


def escape(text):
    """Escapes text to be used in an ldap filter.

    Args:
      text: The text to be escaped

    Returns:
      The escaped text.
    """
    return ldap.filter.escape_filter_chars(text)


class Domain(object):
    """Represents an Active Directory Domain.

    The Domain object performs all interactions with Active Directory, including
    searching for objects, modifying objects, and deleting objects.  Some tasks
    that can be called from a method of an ADObject, like delete() actually
    call the parent Domain object's method to do the dirty work.
    """

    def __init__(self):
        """Initialize the Domain object."""
        self._connected = False
        self.dn_root = ''
        self.dn_forest = ''
        self.dn_schema = ''
        self.dn_configuration = ''
        self._ldap = None

    def __repr__(self):
        if self._connected:
            return 'Domain: %s' % self.dn_root
        else:
            return 'Domain: Not Connected'

    def connect(self, ldap_host, user, password, cert_dir=None, cert_file=None):
        """connect to the ldap server.

        Args:
          ldap_host:  The ldap host to connect to
          user: the username for authentication, must be given with @sufix, ie. user@domain.local. This is important
            if user has dot as part of username like first.last name
          password: the password for authentication
          cert_dir: The directory containing the SSL cert file
          cert_file: The file name of the cert

        Raises:
          errors.LDAPConnectionFailed: if no ldap connection can be made
          errors.InvalidCredentials: if the ldap credentials are not accepted
        """

        if self._connected:
            self.disconnect()

        if cert_dir:
            ldap.set_option(ldap.OPT_X_TLS_CACERTDIR, cert_dir)

        if cert_file:
            ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, cert_file)

        try:
            # Must set this when using self-signed ceritificate on LDAP server
            ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
            self._ldap = ldap.initialize(ldap_host)
            self._ldap.protocol_version = 3
            self._ldap.set_option(ldap.OPT_REFERRALS, 0)

            self._ldap.simple_bind_s(user, password)
            self._connected = True
            self.get_root_dse_attrs()
        except ldap.SERVER_DOWN, e:
            raise errors.LDAPConnectionFailed(e.args[0]['info'])
        except ldap.INVALID_CREDENTIALS:
            raise errors.InvalidCredentials

    def disconnect(self):
        """Disconnects from ldap."""
        self._ldap.unbind_s()
        self._ldap = None
        self.dn_root = ''
        self._connected = False

    def get_root_dse_attrs(self):
        """Gets the root DSE attributes."""
        root_dse = self.search('objectClass=*', scope=ldap.SCOPE_BASE, base_dn='')[0]
        self.dn_root = root_dse.properties['defaultNamingContext'][0]
        self.dn_forest = root_dse.properties['defaultNamingContext'][0]
        self.dn_schema = root_dse.properties['schemaNamingContext'][0]
        self.dn_configuration = root_dse.properties['configurationNamingContext'][0]

    @property
    def dns_name(self):
        """Constructs the dns name of the domain from the distinguished name."""
        elements = self.dn_root.split(',')
        head = []

        for element in elements:
            if re.search('dc\=', element, re.IGNORECASE):
                head.append(element.split('=')[1])
        return '%s' % '.'.join(head)

    def search(self, ldap_filter, base_dn=None, obj_class=None,
               scope=ldap.SCOPE_SUBTREE, properties=None):
        """Searches ActiveDirectory for objects that match the ldap filter.

        Args:
          ldap_filter: an LDAP filter
          base_dn: the distinguished name of the container to start in
          obj_class: can be any class that inherits from ADObject
          scope: one of the ldap SCOPE_ constants
          properties: a list of properties to retrieve

        Returns:
          A list of objects.

        Raises:
          errors.QueryTimeout: if the timeout period is exceeded
          errors.ADDomainNotConnected: if a search is attempted before calling
                                            connect() on the Domain object
        """
        if not self._connected:
            raise errors.ADDomainNotConnected

        raw = []
        results = []
        result_class = obj_class
        page_size = 500

        if not base_dn:
            base_dn = self.dn_root

        if not result_class:
            result_class = ADObject

        lc = ldap.controls.SimplePagedResultsControl(True, size=page_size, cookie='')

        try:
            msgid = self._ldap.search_ext(base_dn, scope,
                                          ldap_filter,
                                          properties,
                                          serverctrls=[lc])
        except ldap.TIMELIMIT_EXCEEDED:
            raise errors.QueryTimeout

        while True:
            rtype, rdata, rmsgid, serverctrls = self._ldap.result3(msgid)

            for data in rdata:
                raw.append(data)

            page_controls = [c for c in serverctrls if c.controlType == lc.controlType]

            if page_controls:
                if page_controls[0].cookie:
                    lc.cookie = page_controls[0].cookie
                    msgid = self._ldap.search_ext(
                        base_dn,
                        scope,
                        ldap_filter,
                        attrlist=properties,
                        serverctrls=[lc]
                    )
                else:
                    break  # There is no more data to fetch
            else:
                break  # AD seems to not return page controls when the total size of
                # the data is less than the page size.

        for result in raw:
            if result[0] is None:
                continue

            for prop in constants.MANDATORY_PROPS_DEFAULT:
                if prop not in result[1]:
                    result[1][prop] = ['']
            result[1]['distinguishedName'] = [result[0]]
            obj = result_class(result[0], properties=result[1], domain_obj=self)
            results.append(obj)

        return results

    def new_object(self, distinguished_name, properties):
        """Creates a new object in Active Directory.

        Args:
          distinguished_name: the desired distinguished name of the object
          properties: a hash of properties and values to apply to the new object

        Note:  Join one of the constants.CAT_ constants with the Domain object's
               dn_configuration property to get a DN for objectCategory.
               (e.g. 'objectCategory': '%s%s'
                % (constants.CAT_USER, ad.dn_configuration))
               Each object also needs the correct objectClass.  Check out the
               constants.CLASS_* constants.
               Also, don't forget that the values of the properties hash should
               all be lists, even if they are single-valued attributes.

        Returns:
          True on success
          False on failure

        Raises:
          errors.ADDomainNotConnected: if used before calling connect()
        """
        if not self._connected:
            raise errors.ADDomainNotConnected

        modlist = ldap.modlist.addModlist(properties)
        self._ldap.add_s(distinguished_name, modlist)

    def update_object(self, distinguished_name, current_props, updated_props):
        """Updates an object in Active Directory.

        Args:
          distinguished_name: the distinguished name of the object to be modified
          current_props: a dict of the current properties and values
          updated_props: a dict of the new properties and values

        Returns:
          True on success
          False on failure

        Raises:
          errors.ADDomainNotConnected: if used before calling connect()
        """
        if not self._connected:
            raise errors.ADDomainNotConnected

        mod = ldap.modlist.modifyModlist(current_props, updated_props)
        result = self._ldap.modify_s(distinguished_name, mod)

        if result[0] == 103:
            return True

    def delete_object(self, distinguished_name):
        """delete an object from Active Directory.

        Args:
          distinguished_name: the full distinguished name of the object

        Raises:
          errors.ADDomainNotConnected: if used before calling connect()
        """
        if not self._connected:
            raise errors.ADDomainNotConnected

        self._ldap.delete_s(distinguished_name)

    def get_object_by_name(self, name):
        """Get an ADObject from AD based on its sAMAccountName.

        Args:
          name: the Windows username (sAMAccountName) of the user

        Returns:
          An ADObject object on success, nothing if no user found.
        """
        result = self.search('sAMAccountName=%s' % escape(name))

        if result:
            return result[0]

    def get_user_by_name(self, user_name):
        """Get a user object from AD based on its sAMAccountName.

        Args:
          user_name: the Windows username (sAMAccountName) of the user

        Returns:
          A user object on success, nothing if no user found.
        """
        result = self.search('sAMAccountName=%s'
                             % escape(user_name), obj_class=User)

        if result:
            return result[0]

        raise errors.ADObjectNotFound('User %s not found' % (user_name))

    def get_computer_by_name(self, computer_name):
        """Get a Computer object from AD based on its hostname.

        Args:
          computer_name: the hostname of the computer.  can be fqdn, sAMAccountName,
                         or computername
        Returns:
          A Computer object on success, nothing if no computer found.
        """
        account = constants.RE_HOSTNAME.match(computer_name).group()

        if account[-1] != '$':
            account += '$'

        result = self.search('sAMAccountName=%s'
                             % escape(account), obj_class=Computer)

        if result:
            return result[0]

    def get_group_by_name(self, group_name):
        """Get a Group object from AD based on its hostname.

        Args:
          group_name: the name of the group.
        Returns:
          A Group object on success, nothing if no computer found.
        """
        result = self.search('sAMAccountName=%s'
                             % escape(group_name), obj_class=Group)

        if result:
            return result[0]

    def get_object_by_dn(self, distinguished_name):
        """Gets an ADObject object based on the distinguished name(DN).

        Args:
          distinguished_name:  A string with the distinguished name of the object

        Returns:
          An ADObject object on success, nothing if no user found.
        """
        ldap_filter = '(distinguishedName=%s)' % escape(distinguished_name)
        result = self.search(ldap_filter, obj_class=User)

        if result:
            return result[0]

    def get_user_by_dn(self, distinguished_name):
        """Gets a User object based on the distinguished name(DN).

        Args:
          distinguished_name:  A string with the distinguished name of the object

        Returns:
          A User object on success, nothing if no user found.
        """
        ldap_filter = ('(&(distinguishedName=%s)(objectCategory=%s%s))'
                       % (escape(distinguished_name),
                          constants.CAT_USER,
                          self.dn_configuration))
        result = self.search(ldap_filter, obj_class=User)

        if result:
            return result[0]

    def get_computer_by_dn(self, distinguished_name):
        """Gets a Computer object based on the distinguished name(DN).

        Args:
          distinguished_name:  A string with the distinguished name of the object

        Returns:
          A Computer object on success, nothing if no computer found.
        """
        ldap_filter = ('(&(distinguishedName=%s)(objectCategory=%s%s))'
                       % (escape(distinguished_name),
                          constants.CAT_COMPUTER,
                          self.dn_configuration))
        result = self.search(ldap_filter, obj_class=Computer)

        if result:
            return result[0]

    def get_group_by_dn(self, distinguished_name):
        """Gets a Group object based on the distinguished name(DN).

        Args:
          distinguished_name:  A string with the distinguished name of the object

        Returns:
          A User object on success, nothing if no user found.
        """
        ldap_filter = ('(&(distinguishedName=%s)(objectCategory=%s%s))'
                       % (escape(distinguished_name),
                          constants.CAT_GROUP,
                          self.dn_configuration))
        result = self.search(ldap_filter, obj_class=Group)

        if result:
            return result[0]

    def get_container_by_dn(self, distinguished_name):
        """Gets a Group object based on the distinguished name(DN).

        Args:
          distinguished_name:  A string with the distinguished name of the object

        Returns:
          A Group object on success, nothing if no group found.
        """
        ldap_filter = ''.join(['(&(distinguishedName=%s)'
                               % escape(distinguished_name),
                               '(|(objectCategory=%s%s)'
                               % (constants.CAT_CN, self.dn_configuration),
                               '(objectCategory=%s%s)'
                               % (constants.CAT_DOMAIN, self.dn_configuration),
                               '(objectCategory=%s%s)))'
                               % (constants.CAT_OU, self.dn_configuration)])
        result = self.search(ldap_filter, obj_class=Container)

        if result:
            return result[0]

    def guess_object_type(self, obj):
        """Try to find the best ad_ldap object class for the object.

        Args:
          obj: an ADObject object

        Raises:
          errors.ADObjectClassOnly: if the object passed is not an ADObject

        Returns:
          If the object type can be guessed: return an object of that class for
                                             the same distinguished name
          Otherwise return the object unchanged.
        """
        if not isinstance(obj, ADObject):
            raise errors.ADObjectClassOnly

        if 'CN=Computer' in obj.object_category:
            return self.get_computer_by_dn(obj.distinguished_name)
        elif 'CN=Person' in obj.object_category:
            return self.get_user_by_dn(obj.distinguished_name)
        elif 'CN=Group' in obj.object_category:
            return self.get_group_by_dn(obj.distinguished_name)
        elif 'CN=Container' in obj.object_category:
            return self.get_container_by_dn(obj.distinguished_name)
        elif 'CN=Organizational-Unit' in obj.object_category:
            return self.get_container_by_dn(obj.distinguished_name)
        else:
            return obj


class ADObject(object):
    """A generic AD Object."""

    def __init__(self, distinguished_name, properties, domain_obj):
        """Initialize the AD object.

        Args:
          distinguished_name: the full distinguished name of the object
          properties: if a list, a list of properties to retrieve.  if a hash, it is
                      a pre-populated list of properties.  If a hash is provided and
                      mandatory properties are missing, then they will be retrieved
                      by an ldap query
          domain_obj: the Domain object that the AD object is associated with
        """
        get_props = []
        self.properties = dict()
        self.properties['distinguishedName'] = [distinguished_name]
        self._property_snapshot = {}

        if isinstance(properties, dict):
            self.properties = properties
            for prop in constants.MANDATORY_PROPS_DEFAULT:
                if prop not in properties:
                    get_props.append(prop)
        elif isinstance(properties, list):
            for prop in constants.MANDATORY_PROPS_DEFAULT:
                if prop not in properties:
                    properties.append(prop)

            get_props = properties

        self._domain_obj = domain_obj

        if get_props:
            self.get_properties(get_props)

        self._property_snapshot = copy.deepcopy(self.properties)

    def __repr__(self):
        return 'ADObject: %s' % self.distinguished_name

    @property
    def distinguished_name(self):
        return self.properties['distinguishedName'][0]

    @property
    def object_class(self):
        return self.properties['objectClass']

    @property
    def object_category(self):
        return self.properties['objectCategory'][0]

    @property
    def created_time(self):
        if not self.properties['whenCreated'][0]:
            return 0
        else:
            return text_time_to_unix(self.properties['whenCreated'][0])

    @property
    def modified_time(self):
        if not self.properties['whenChanged'][0]:
            return 0
        else:
            return text_time_to_unix(self.properties['whenChanged'][0])

    @property
    def canonical_name(self):
        """Constructs the canonical name from the distinguished name."""
        elements = self.distinguished_name.split(',')
        head = []
        tail = []

        for element in elements:
            if re.search('dc\=', element, re.IGNORECASE):
                head.append(element.split('=')[1])
            else:
                tail.append(element.split('=')[1])

        tail.reverse()
        return '%s\\%s' % ('.'.join(head), '\\'.join(tail))

    def get_properties(self, properties):
        """Updates self.properties with the values from AD.

        Args:
          properties: a list of properties to retrieve

        Raises:
          errors.NonListParameter: if a string is passed instead of a list
        """
        if properties.__class__.__name__ in ('str', 'unicode'):
            raise errors.NonListParameter

        ldap_filter = 'distinguishedName=%s' % escape(self.distinguished_name)
        result = self._domain_obj.search(ldap_filter,
                                         properties=properties)
        if result:
            for prop in result[0].properties:
                self.properties[prop] = result[0].properties[prop]
                self._property_snapshot[prop] = result[0].properties[prop]

    def refresh(self):
        """Update all properties with values from AD."""
        self.get_properties([x for x in self.properties])

    def move(self, destination):
        """move an AD object from one part of the directory to another.

        Args:
          destination: the destination DN
        """
        prefix = None

        try:
            prefix = 'CN=%s' % constants.RE_CN.findall(self.distinguished_name)[0]
        except IndexError:
            prefix = 'OU=%s' % constants.RE_OU.findall(self.distinguished_name)[0]

        self.properties['distinguishedName'] = '%s,%s' % (prefix, destination)
        self.set_properties()

    def delete(self):
        """delete the current object from AD."""
        self._domain_obj.delete_object(self.distinguished_name)
        self.properties = {}
        self._property_snapshot = {}

    def set_properties(self):
        """Write changed properties to Active Directory.

        Note: A property must be retrieved at least once before updating.

        Returns:
          True: on success
          False: on failure
        """
        old = {}
        new = {}

        for prop in self._property_snapshot:
            if self._property_snapshot[prop] != self.properties[prop]:
                new[prop] = self.properties[prop]
                old[prop] = self._property_snapshot[prop]

        for prop in self.properties:
            if prop not in self._property_snapshot:
                self._property_snapshot[prop] = [None]

        result = self._domain_obj.update_object(self.distinguished_name, old, new)

        if result:
            self._property_snapshot = copy.deepcopy(self.properties)
            return True
        else:
            return False


class User(ADObject):
    """An Active Directory user object.

    This class exposes user-specific properties and also adds methods for locking,
    unlocking, disabling and enabling accounts.
    """

    def __init__(self, distinguished_name, properties, domain_obj):
        ADObject.__init__(self, distinguished_name, properties, domain_obj)
        get_props = []

        if isinstance(properties, dict):
            self.properties = properties

            for prop in constants.MANDATORY_PROPS_USER:
                if prop not in properties:
                    get_props.append(prop)
        elif isinstance(properties, list):
            for prop in constants.MANDATORY_PROPS_USER:
                if prop not in properties:
                    properties.append(prop)

            get_props = properties

        if get_props:
            self.get_properties(get_props)

        self._property_snapshot = copy.deepcopy(self.properties)

    def __repr__(self):
        return 'User: %s' % constants.RE_CN.findall(self.distinguished_name)[0]

    @property
    def user_account_control(self):
        return int(self.properties['userAccountControl'][0])

    @property
    def msds_ua_control_computed(self):
        return int(self.properties['msDS-User-Account-Control-Computed'][0])

    @property
    def display_name(self):
        return self.properties['displayName'][0]

    @property
    def username(self):
        return self.properties['sAMAccountName'][0]

    @property
    def disabled(self):
        return bitmask_bool(self.user_account_control,
                            constants.ADS_UF_ACCOUNTDISABLE)

    @property
    def locked_out(self):
        return bitmask_bool(self.msds_ua_control_computed,
                            constants.ADS_UF_LOCKOUT)

    @property
    def pwd_expired(self):
        return bitmask_bool(self.msds_ua_control_computed,
                            constants.ADS_UF_PASSWORD_EXPIRED)

    @property
    def pwd_never_expires(self):
        return bitmask_bool(self.user_account_control,
                            constants.ADS_UF_DONT_EXPIRE_PASSWD)

    @property
    def pwd_cant_change(self):
        """
        In most cases this does not work as expected.
        http://www.selfadsi.org/ads-attributes/user-userAccountControl.htm#UF_PASSWD_CANT_CHANGE
        :return: bool
        """
        return bitmask_bool(self.user_account_control, constants.ADS_UF_PASSWD_CANT_CHANGE)

    def unlock(self):
        """unlock the user object in AD.

        Returns:
          True on success
          False on failure

        Raises:
          UserNotLockedOut: if the user is not locked out
        """
        if not self.locked_out:
            raise errors.UserNotLockedOut

        self.properties['lockoutTime'] = ['0']
        self.set_properties()
        self.get_properties(['msDS-User-Account-Control-Computed'])

        if not self.locked_out:
            return True
        else:
            return False

    def disable(self):
        """disable the user object in AD.

        Returns:
          True on success
          False on failure

        Raises:
          UserNotEnabled: if the user is already disabled
        """
        if self.disabled:
            raise errors.UserNotEnabled

        uac = int(self.properties['userAccountControl'][0])
        value = uac | constants.ADS_UF_ACCOUNTDISABLE
        self.properties['userAccountControl'] = [str(value)]
        self.set_properties()

        if self.disabled:
            return True
        else:
            return False

    def enable(self):
        """enable the user object in AD.

        Returns:
          True on success
          False on failure

        Raises:
          UserNotDisabled: if the user is not disabled
        """
        if not self.disabled:
            raise errors.UserNotDisabled

        uac = int(self.properties['userAccountControl'][0])
        value = uac ^ constants.ADS_UF_ACCOUNTDISABLE
        self.properties['userAccountControl'] = [str(value)]
        self.set_properties()

        if not self.disabled:
            return True
        else:
            return False

    def groups(self):
        """
        Get groups that user is member of

        Args:
          self

        Returns:
          List of Group objects user is member of
        """
        ldap_filter = ('(&(objectCategory=group)(member=%s))'
                       % (escape(self.distinguished_name)))
        result = self._domain_obj.search(ldap_filter, obj_class=Group)
        return result

    def in_group(self, group):
        """
        Check if user is member of Group, and if so return True, else return False

        Args:
          self, Group object

        Returns:
          Bool

        """
        ldap_filter = ('(&(memberOf:1.2.840.113556.1.4.1941:=%s)(sAMAccountName=%s))'
                       % (escape(group.distinguished_name), escape(self.username)))
        result = self._domain_obj.search(ldap_filter)
        return len(result) > 0

    def change_password(self, newpassword, oldpassword=None):
        """
        Change user password, must give valid old and valid new password that meets all Domain password policy
        When doing administrative password change (odlpassword=None) some password policies are not checked, like
        old remembered passwords.

        It would be nice if AD would allow us to check if user can change his password, but this option does not work
        as expected. Here is explanation:
        http://www.selfadsi.org/ads-attributes/user-userAccountControl.htm#UF_PASSWD_CANT_CHANGE

        Args:
            self, New password, Old password (optional)

        Returns:
            InvalidCredentials: When given invalid old user password. Note that giving invalid password few times might
            lock user account according to Domain Password Policy
            DoesNotMeetPasswordPolicy: New password does not meed all Domain Password Policies, this includes password
            age, which is by default one day
            InsufficientAccess: User cannot change password
            LDAPError: all other LDAP errors

        """
        newpassword = unicode('\"' + newpassword + '\"').encode('utf-16-le')
        #If given old password encode it and try MOD_DELETE/MOD_ADD password, aka. regular user selfchange password
        #else, try administrative password change, in which case authenticated user must have password change privilege
        #by default that is Domain Administrator
        if oldpassword is not None:
            oldpassword = unicode('\"' + oldpassword + '\"').encode('utf-16-le')
            pass_mod = [(ldap.MOD_DELETE, 'unicodePwd', [oldpassword]), (ldap.MOD_ADD, 'unicodePwd', [newpassword])]
        else:
            pass_mod = [(ldap.MOD_REPLACE, 'unicodePwd', newpassword)]

        try:
            self._domain_obj._ldap.modify_s(self.distinguished_name, pass_mod)
        except ldap.CONSTRAINT_VIOLATION, e:
            # If the exceptions's 'info' field begins with:
            # 00000056 - Current passwords do not match
            # 0000052D - New password violates length/complexity/history
            # 00000005 - Insufficient access, maybe user have 'User cannot change password' option set
            message = 'LDAP Error. desc: %s info: %s' % (e[0]['desc'], e[0]['info'])
            if e[0]['info'].startswith('00000056'):
                # Incorrect current password.
                raise errors.InvalidCredentials(message)
            elif e[0]['info'].startswith('0000052D'):
                #Does not meet password policy
                raise errors.DoesNotMeetPasswordPolicy(message)
            elif e[0]['info'].startswith('00000005'):
                #Either user have 'Cannot change password' option set, or changing user password without old password
                raise errors.InsufficientAccess(message)
            else:
                #When everything fails, return original error
                raise e
        except ldap.LDAPError, e:
            raise errors.ADPasswordSetFailed('LDAP Error. desc: %s info: %s' % (e[0]['desc'], e[0]['info']))


class Computer(User):
    """An Active Directory computer object.

    This class exposes computer-specific properties at the top level to make it
    easier to work with computer objects.  Note that it also inherits from the
    User class.
    """

    def __init__(self, distinguished_name, properties, domain_obj):
        User.__init__(self, distinguished_name, properties, domain_obj)
        get_props = []

        if isinstance(properties, dict):
            self.properties = properties

            for prop in constants.MANDATORY_PROPS_COMPUTER:
                if prop not in properties:
                    get_props.append(prop)
        elif isinstance(properties, list):
            for prop in constants.MANDATORY_PROPS_COMPUTER:
                if prop not in properties:
                    properties.append(prop)

            get_props = properties

        if get_props:
            self.get_properties(get_props)

        self._property_snapshot = copy.deepcopy(self.properties)

    def __repr__(self):
        return 'Computer: %s' % constants.RE_CN.findall(self.distinguished_name)[0]

    @property
    def service_principal_name(self):
        return self.properties['servicePrincipalName']

    @property
    def dns_hostname(self):
        return self.properties['dNSHostName'][0]

    @property
    def os(self):
        return self.properties['operatingSystem'][0]

    @property
    def os_service_pack(self):
        return self.properties['operatingSystemServicePack'][0]

    @property
    def os_version(self):
        return self.properties['operatingSystemVersion'][0]


class Container(ADObject):
    """An Active Directory CN or OU object.

    This class adds the get_children method to make it easier to return a list
    of objects in the container.
    """

    def __repr__(self):
        try:
            return ('Container: %s'
                    % constants.RE_OU.findall(self.distinguished_name)[0])
        except IndexError:
            return ('Container: %s'
                    % constants.RE_CN.findall(self.distinguished_name)[0])

    def get_children(self, recursive=False):
        """Retrieves a list of objects inside the container."""
        output = []
        scope = None

        if recursive:
            scope = ldap.SCOPE_SUBTREE
        else:
            scope = ldap.SCOPE_ONELEVEL

        results = self._domain_obj.search('objectClass=*',
                                          base_dn=self.distinguished_name,
                                          properties=['distinguishedName'],
                                          scope=scope)
        for obj in results:
            output.append(self._domain_obj.guess_object_type(obj))

        return output


class Group(ADObject):
    """An Active Directory Group object.

    This class provides extra methods for manipulating group memberships.
    """

    def __init__(self, distinguished_name, properties, domain_obj):
        ADObject.__init__(self, distinguished_name, properties, domain_obj)
        get_props = []

        if isinstance(properties, dict):
            self.properties = properties

            for prop in constants.MANDATORY_PROPS_GROUP:
                if prop not in properties:
                    get_props.append(prop)
        elif isinstance(properties, list):
            for prop in constants.MANDATORY_PROPS_GROUP:
                if prop not in properties:
                    properties.append(prop)

            get_props = properties

        if get_props:
            self.get_properties(get_props)

        self._property_snapshot = copy.deepcopy(self.properties)

    def __repr__(self):
        return 'Group: %s' % constants.RE_CN.findall(self.distinguished_name)[0]

    def get_members(self):
        """Retrieves a list of objects that are members.

        get_members will try to find the appropriate object type for the member if
        if is a user, computer or group.

        Returns:
          A list of objects.
        """
        members = []
        output = []

        for member in self.properties['member']:
            result = self._domain_obj.search('distinguishedName=%s' % escape(member))

            if result:
                members.append(result[0])

        for obj in members:
            output.append(self._domain_obj.guess_object_type(obj))

        return output

    def add_member(self, user):
        """
        Add single user to group
        :param User object
        :return:
        """
        if not isinstance(user, User):
            raise errors.InvalidObjectType

        member = user.distinguished_name
        if member in self.properties['member']:
            raise errors.ADGroupMemberExistsError

        self.properties['member'].append(member)
        return self.set_properties()

    def add_members(self, member_list):
        """Add list of users to group

        Args:
          member_list: a list of User objects to add to group

        Returns:
          True on success
          False on failure

        Raises:
          errors.MemberExistsError: if the member was already in the group
          errors.NonListParameter: if a string was passed by mistake
        """
        if member_list.__class__.__name__ in ('str', 'unicode'):
            raise errors.NonListParameter

        members_to_add = []

        for user in member_list:
            members_to_add.append(user.distinguished_name)

        for member in members_to_add:
            if member in self.properties['member']:
                raise errors.MemberExist

        self.properties['member'] += members_to_add
        return self.set_properties()

    def delete_members(self, member_list):
        """Remove one user from the group.

        Args:
          member_list: a list of the sAMAccountNames of the users to remove

        Returns:
          True on success
          False on failure

        Raises:
          errors.NonListParameter: if a string was passed by mistake
          errors.ADGroupMemberDoesNotExistError: if the object to be removed is not
                                                 a member
        """
        if member_list.__class__.__name__ in ('str', 'unicode'):
            raise errors.NonListParameter

        members_to_remove = []

        for user in member_list:
            if user.distinguished_name not in self.properties['member']:
                raise errors.NotAMember

            members_to_remove.append(user.distinguished_name)

        members_to_remove = set(members_to_remove)
        current = set(self.properties['member'])
        new_list = list(current - members_to_remove)

        if not new_list:
            new_list = []

        self.properties['member'] = new_list
        return self.set_properties()

    def overwrite_members(self, member_list):
        """Overwrite the member list with a list of users.

        Args:
          member_list:  a list of User objects or Group objects

        Returns:
          True on success
          False on failure

        Raises:
          errors.NonListParameter: if a string was passed by mistake
        """
        if member_list.__class__.__name__ in ('str', 'unicode'):
            raise errors.NonListParameter

        members = []

        for name in member_list:
            members.append(name.distinguished_name)

        old_members = set(self.properties['member'])
        new_members = set(members)

        # If the members are the same, it's a no-op.
        if old_members == new_members:
            return True

        self.properties['member'] = members
        return self.set_properties()