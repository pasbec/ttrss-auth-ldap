# ttrss-auth-ldap

LDAP authentication plugin for [Tiny Tiny RSS](https://tt-rss.org) forked from [TTRSS-Auth-LDAP](https://github.com/hydrian/TTRSS-Auth-LDAP) - cleaned up, updated. Active Directory authentication is now also supported without some dedicated bind-account. A full Docker Compose example setup can be found [here](https://github.com/pasbec/ttrss-docker-compose).

## Setup

1. Follow Tiny Tiny RSS [docker installation guide](https://tt-rss.org/wiki/InstallationNotes) but build your own image by using some simple `Dockerfile` like
    ```Dockerfile
    FROM cthulhoo/ttrss-fpm-pgsql-static:latest

    RUN apk add php83-ldap

    # Plugins
    WORKDIR /var/www/html/tt-rss/plugins.local
    RUN git clone https://github.com/pasbec/ttrss-auth-ldap.git auth_ldap
    # ...

    WORKDIR /opt/tt-rss
    ```
1. Enable the plugin by adding `auth_ldap` to `TTRSS_PLUGINS`, e.g.
    ```ini
     TTRSS_PLUGINS=auth_ldap, auth_internal, note, nginx_xaccel
    ```
1. Configure the plugin via its own environment variables:

    ```ini
    # Example for Active Directory search with extended attribute retrieval, user/admin filters and support for nested groups without requiring separate bind account
    TTRSS_LDAP_URI=ldap://dc.some.example.com
    TTRSS_LDAP_USE_TLS=true # optional
    TTRSS_LDAP_BASE_DN=CN=Users,DC=some,DC=example,DC=com
    TTRSS_LDAP_BIND_DN=SOME\{login}
    TTRSS_LDAP_BIND_PW={password}
    TTRSS_LDAP_ADMIN_FILTER=(&(objectClass=person)(memberOf:1.2.840.113556.1.4.1941:=CN=TinyTinyRSS-Admins,CN=Users,DC=some,DC=example,DC=com)(sAMAccountName={login}))
    TTRSS_LDAP_USER_FILTER=(&(objectClass=person)(memberOf:1.2.840.113556.1.4.1941:=CN=TinyTinyRSS-Users,CN=Users,DC=some,DC=example,DC=com)(sAMAccountName={login}))
    TTRSS_LDAP_USER_ATTRIBUTE=sAMAccountName
    TTRSS_LDAP_NAME_ATTRIBUTE=name # optional
    TTRSS_LDAP_MAIL_ATTRIBUTE=mail # optional

    # General example using dedicated bind account
    TTRSS_LDAP_URI=ldap://localhost
    TTRSS_LDAP_USE_TLS=false # optional
    TTRSS_LDAP_BASE_DN=DC=example,DC=com
    TTRSS_LDAP_BIND_DN=CN=some-bind-user,DC=example,DC=com
    TTRSS_LDAP_BIND_PW=<SOME_BIND_USER_PASSWORD>
    TTRSS_LDAP_USER_FILTER=(&(objectClass=person)(uid={login}))
    TTRSS_LDAP_USER_ATTRIBUTE=uid

    # General example using anonymous bind
    TTRSS_LDAP_URI=ldap://localhost
    TTRSS_LDAP_USE_TLS=false # optional
    TTRSS_LDAP_BASE_DN=DC=example,DC=com
    TTRSS_LDAP_USER_FILTER=(&(objectClass=person)(uid={login}))
    TTRSS_LDAP_USER_ATTRIBUTE=uid
    ```