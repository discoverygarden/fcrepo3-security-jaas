# DGI JAAS Implementations

## Introduction

Workaround implementations.

The stock `org.fcrepo.server.security.jaas.auth.module.XmlUsersFileModule` class uses the Xerces XML parser between multiple thread; however, [this parser is _not_ thread safe](https://issues.apache.org/jira/browse/XERCESJ-211?focusedCommentId=33322&page=com.atlassian.jira.plugin.system.issuetabpanels:comment-tabpanel#comment-33322). This results in a race condition that can prevent users specific in the XML file from being able to login.

## Building

```
FEDORA_VERSION="3.6.2"
git clone git@github.com:discoverygarden/fcrepo3-security-jaas.git
cd fcrepo3-security-jaas
mvn package -Dfedora.version=$FEDORA_VERSION
```

Builds against 3.6.2 and generates a JAR in `fcrepo3-security-jaas/target`.

## Installation

1. Drop the built JAR into your `$CATALINA_HOME/webapps/fedora/WEB-INF/lib`; and,
2. Update references in your `$FEDORA_HOME/server/config/jaas.conf` from `org.fcrepo.server.security.jaas.auth.module.XmlUsersFileModule` to `ca.discoverygarden.fcrepo3.security.jaas.XmlUsersFileModule`.
3. If Fedora is running, restart it so it picks up the new configuration.

## Troubleshooting/Issues

Having problems or solved a problem? Contact [discoverygarden](http://support.discoverygarden.ca).

## Maintainers/Sponsors

Current maintainers:

* [discoverygarden](http://www.discoverygarden.ca)

## Development

If you would like to contribute to this module, please contact us at [discoverygarden](http://support.discoverygarden.ca).

## License

[GPLv3](http://www.gnu.org/licenses/gpl-3.0.txt)
