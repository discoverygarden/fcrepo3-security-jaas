# DGI JAAS Implementations

## Introduction

Workaround implementations.

The stock `org.fcrepo.server.security.jaas.auth.module.XmlUsersFileModule` class uses the Xerces XML parser between multiple thread; however, [this parser is _not_ thread safe](https://issues.apache.org/jira/browse/XERCESJ-211?focusedCommentId=33322&page=com.atlassian.jira.plugin.system.issuetabpanels:comment-tabpanel#comment-33322). This results in a race condition that can prevent users specific in the XML file from being able to login.

## Building

```bash
FEDORA_VERSION="3.6.2"
# We are dependent on the islandora_drupal_filter, so install into the local
# Maven repo.
git clone git@github.com:Islandora/islandora_drupal_filter.git
cd islandora_drupal_filter
mvn -Dfedora.version=$FEDORA_VERSION install
cd ..

# Now, let's get ourselves built.
git clone git@github.com:discoverygarden/fcrepo3-security-jaas.git
cd fcrepo3-security-jaas
mvn package -Dfedora.version=$FEDORA_VERSION
```

Builds against 3.6.2 and generates a JAR in `fcrepo3-security-jaas/target`.

## Installation

1. Drop the built JAR into your `$CATALINA_HOME/webapps/fedora/WEB-INF/lib`

### `XMLUsersFileModule` thread-safety

After installing the JAR:

1. Update references in your `$FEDORA_HOME/server/config/jaas.conf` from `org.fcrepo.server.security.jaas.auth.module.XmlUsersFileModule` to `ca.discoverygarden.fcrepo3.security.jaas.module.XmlUsersFileModule`.
2. If Fedora is running, restart it so it picks up the new configuration.

### Multisite Optimization

The original `DrupalAuthModule` implementation requires iterating through all configured connection when authenticating users, and for repositories connected to many sites, this iteration can be slow (and unavailable sites may even result in timeouts); therefore, it is desirable if it was possible to more directly select which against which to attempt authentication.

The `DrupalMultisiteAuthModule` looks for `key` attributes on each connection element, which must match the `key` obtained from the HTTP request in our `ca.discoverygarden.fcrepo3.security.jaas.filter.AuthFilterJAAS` implementation (by default, the `User-Agent` header because it is easily modified for requests from Tuque; configurable to other headers using the `keyHeader` property in the Spring bean configuration).

See [the documentation](/docs/multisite-optimization.md) for more details.

## Troubleshooting/Issues

Having problems or solved a problem? Contact [discoverygarden](http://support.discoverygarden.ca).

## Maintainers/Sponsors

Current maintainers:

* [discoverygarden](http://www.discoverygarden.ca)

## Development

If you would like to contribute to this module, please contact us at [discoverygarden](http://support.discoverygarden.ca).

## License

[GPLv3](http://www.gnu.org/licenses/gpl-3.0.txt)
