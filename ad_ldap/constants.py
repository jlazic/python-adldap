#!/usr/bin/python
"""A module containing constants used by adldap module.

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

import re

# Properties that must be included by default for any ADObject
MANDATORY_PROPS_DEFAULT = ('distinguishedName', 'objectClass', 'objectCategory',
                           'name', 'description', 'createTimeStamp',
                           'modifyTimeStamp')

# Default properties for User objects
MANDATORY_PROPS_USER = MANDATORY_PROPS_DEFAULT + (
    'sAMAccountName', 'msDS-User-Account-Control-Computed', 'memberOf')

# Default properties for Computer objects
MANDATORY_PROPS_COMPUTER = MANDATORY_PROPS_USER + (
    'servicePrincipalName', 'dNSHostname', 'operatingSystem',
    'operatingSystemServicePack', 'operatingSystemVersion')

# Default properties for Group objects
MANDATORY_PROPS_GROUP = MANDATORY_PROPS_DEFAULT + ('groupType',)

# ADS_USER_FLAG_ENUM as listed by Microsoft.  It defines flags in the
# userAccountControl bitmask.  Doing a bitwise AND between the
# userAccountControl attribute of a user and the constant will tell you if
# that boolean option is set on their account
ADS_UF_SCRIPT = 1
ADS_UF_ACCOUNTDISABLE = 2
ADS_UF_HOMEDIR_REQUIRED = 8
ADS_UF_LOCKOUT = 16
ADS_UF_PASSWD_NOTREQD = 32
ADS_UF_PASSWD_CANT_CHANGE = 64
ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED = 128
ADS_UF_TEMP_DUPLICATE_ACCOUNT = 256
ADS_UF_NORMAL_ACCOUNT = 512
ADS_UF_INTERDOMAIN_TRUST_ACCOUNT = 2048
ADS_UF_WORKSTATION_TRUST_ACCOUNT = 4096
ADS_UF_SERVER_TRUST_ACCOUNT = 8192
ADS_UF_DONT_EXPIRE_PASSWD = 65536
ADS_UF_MNS_LOGON_ACCOUNT = 131072
ADS_UF_SMARTCARD_REQUIRED = 262144
ADS_UF_TRUSTED_FOR_DELEGATION = 524288
ADS_UF_NOT_DELEGATED = 1048576
ADS_UF_USE_DES_KEY_ONLY = 2097152
ADS_UF_DONT_REQUIRE_PREAUTH = 4194304
ADS_UF_PASSWORD_EXPIRED = 8388608
ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 16777216

# The difference in 100ns ticks between the Microsoft epoch (Jan 1, 1601) and
# the Unix epoch (Jan 1, 1970) for use in ad_time_to_unix
EPOCH_AS_FILETIME = 116444736000000000

# For attributes in YYYYMMDDHHMMSS.0Z format
RE_TEXT_TIME = re.compile('^(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)\.0Z$')

# For getting the compturname from an FQDN
RE_HOSTNAME = re.compile('^[^.]+')

# These pull the CN or OU value of the distinguishedName
RE_CN = re.compile('^CN=([^,]+)')
RE_OU = re.compile('^OU=([^,]+)')

# Prefixes for objectCategory attributes to help with identifying objects
CAT_USER = 'CN=Person,CN=Schema,'
CAT_COMPUTER = 'CN=Computer,CN=Schema,'
CAT_GROUP = 'CN=Group,CN=Schema,'
CAT_OU = 'CN=Organizational-Unit,CN=Schema,'
CAT_CN = 'CN=Container,CN=Schema,'
CAT_DOMAIN = 'CN=Domain-DNS,CN=Schema,'

# The set of objectClass values required for each kind of object
CLASS_USER = ['organizationalPerson', 'person', 'top', 'user']
CLASS_COMPUTER = ['computer', 'organizationalPerson', 'person', 'top', 'user']
CLASS_OU = ['organizationalUnit', 'top']
CLASS_GROUP = ['group', 'top']
