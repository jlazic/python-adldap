#!/usr/bin/python
"""A module containing the exception classes for the adldap module.

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


class Error(Exception):
    """Generic Error class for adldap."""

class AccountPasswordExpired(Error):
    """An attempt was made to bind with account with expired password."""

class InvalidObjectType(Error):
    """Given object is invalid type"""


class ObjectPropertyNotFound(Error):
    """An attempt was made to access a property that was not found."""


class UserNotDisabled(Error):
    """An attempt was made to enable a user that was not disabled."""


class UserNotEnabled(Error):
    """An attempt was made to disable a user that was not enabled."""


class UserNotLockedOut(Error):
    """An attempt was made to unlock a user that is not locked out."""


class NoComputerPasswordReset(Error):
    """Resetting the password for computer objects is not supported."""


class LDAPConnectionFailed(Error):
    """The LDAP server could not be contacted."""


class InvalidCredentials(Error):
    """The credentials supplied were invalid."""


class DoesNotMeetPasswordPolicy(Error):
    """Given password does not meet LDAP password policy"""


class InsufficientAccess(Error):
    """Raise when authenticated user does not have enough privileges"""


class QueryTimeout(Error):
    """The ldap query timed out waiting for results."""


class InvalidPropertyFormat(Error):
    """The properties requested for the object are in an invalid format."""


class ADObjectClassOnly(Error):
    """These results can only be retrieved when using the ADObject class type."""


class ADObjectNotFound(Error):
    """The search returned zero results."""


class ADDomainNotConnected(Error):
    """You must call connect() on the Domain object before this operation."""


class ADPasswordSetFailed(Error):
    """The attempt to update the password failed."""


class MemberExist(Error):
    """The group member already exists."""


class NotAMember(Error):
    """The object is not a member of the group."""


class NonListParameter(Error):
    """The parameter must be a list or other iterable."""