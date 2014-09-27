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


class InvalidObjectType(Error):
    """Given object is invalid type"""


class ObjectPropertyNotFoundError(Error):
    """An attempt was made to access a property that was not found."""


class UserNotDisabledError(Error):
    """An attempt was made to enable a user that was not disabled."""


class UserNotEnabledError(Error):
    """An attempt was made to disable a user that was not enabled."""


class UserNotLockedOutError(Error):
    """An attempt was made to unlock a user that is not locked out."""


class NoComputerPasswordResetError(Error):
    """Resetting the password for computer objects is not supported."""


class LDAPConnectionFailedError(Error):
    """The LDAP server could not be contacted."""


class InvalidCredentialsError(Error):
    """The credentials supplied were invalid."""


class DoesNotMeetPasswordPolicyError(Error):
    """Given password does not meet LDAP password policy"""


class QueryTimeoutError(Error):
    """The ldap query timed out waiting for results."""


class InvalidPropertyFormatError(Error):
    """The properties requested for the object are in an invalid format."""


class ADObjectClassOnlyError(Error):
    """These results can only be retrieved when using the ADObject class type."""


class ADObjectNotFoundError(Error):
    """The search returned zero results."""


class ADDomainNotConnectedError(Error):
    """You must call connect() on the Domain object before this operation."""


class ADPasswordSetFailedError(Error):
    """The attempt to update the password failed."""


class MemberExistError(Error):
    """The group member already exists."""


class NotAMemberError(Error):
    """The object is not a member of the group."""


class NonListParameterError(Error):
    """The parameter must be a list or other iterable."""


class ServerRefusedOperationError(Error):
    """The server refused to perform the operation requested."""
