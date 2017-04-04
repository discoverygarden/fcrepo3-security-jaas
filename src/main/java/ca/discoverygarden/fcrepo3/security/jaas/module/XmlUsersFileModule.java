/*
 * File: XmlUsersFileModule.java
 *
 * Copyright 2009 Muradora
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

package ca.discoverygarden.fcrepo3.security.jaas.module;

import java.io.File;
import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

import org.fcrepo.common.Constants;
import org.fcrepo.server.security.jaas.auth.UserPrincipal;
import org.fcrepo.server.security.jaas.util.DataUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

/**
 * Adjusted copypasta of
 * org.fcrepo.server.security.jaas.auth.module.XmlUsersFileModule.
 *
 * Primarily, to avoid thread-unsafe behaviour with DOM parsing, and to adjust
 * the visibility of "private" member to "protected", to facilitate overriding
 * in subclasses.
 *
 * @see org.fcrepo.server.security.jaas.auth.module.XmlUsersFileModule
 */
public class XmlUsersFileModule
implements LoginModule {
    protected static final Logger logger =
            LoggerFactory.getLogger(XmlUsersFileModule.class);

    protected static File userFile = getUsersFile();

    // must be marked volatile for double-checked locking in caching method to work
    protected static volatile long userFileParsed = Long.MIN_VALUE;

    protected static volatile long userFileBytesLoaded = 0L;

    protected static Map<User, FullUserInfo> users;

    protected Subject subject = null;

    protected CallbackHandler handler = null;

    protected Map<String, ?> options = null;

    protected UserPrincipal principal = null;

    protected Map<String, Set<String>> attributes = null;

    protected boolean debug = false;

    protected boolean successLogin = false;

    public void initialize(Subject subject,
            CallbackHandler handler,
            Map<String, ?> sharedState,
            Map<String, ?> options) {
        this.subject = subject;
        this.handler = handler;
        this.options = options;

        String debugOption = (String) this.options.get("debug");
        if (debugOption != null && "true".equalsIgnoreCase(debugOption)) {
            debug = true;
        }

        attributes = new HashMap<String, Set<String>>();

        if (debug) {
            logger.debug("login module initialised: {}", this.getClass().getName());
        }
    }

    public boolean login() throws LoginException {
        if (debug) {
            logger.debug(this.getClass().getName() + " login called.");
        }

        if (Constants.FEDORA_HOME == null || "".equals(Constants.FEDORA_HOME.trim())) {
            logger.error("FEDORA_HOME constant is not set");
            return false;
        }

        final NameCallback nc = new NameCallback("username");
        final PasswordCallback pc = new PasswordCallback("password", false);
        final Callback[] callbacks = new Callback[] {
                nc, pc
        };

        try {
            handler.handle(callbacks);
        } catch (IOException ioe) {
            ioe.printStackTrace();
            throw new LoginException("IOException occured: " + ioe.getMessage());
        } catch (UnsupportedCallbackException ucbe) {
            ucbe.printStackTrace();
            throw new LoginException("UnsupportedCallbackException encountered: "
                    + ucbe.getMessage());
        }

        // Grab the username and password from the callbacks.
        final String username = nc.getName();
        final String password = new String(pc.getPassword());

        successLogin = authenticate(username, password);

        return successLogin;
    }

    public boolean commit() throws LoginException {
        if (!successLogin) {
            return false;
        }

        try {
            subject.getPrincipals().add(principal);
            subject.getPublicCredentials().add(attributes);
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            return false;
        }

        return true;
    }

    public boolean abort() throws LoginException {
        try {
            clear();
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            return false;
        }

        return true;
    }

    public boolean logout() throws LoginException {
        try {
            clear();
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            return false;
        }

        return true;
    }

    protected void clear() {
        subject.getPrincipals().clear();
        subject.getPublicCredentials().clear();
        subject.getPrivateCredentials().clear();
        principal = null;
    }

    protected boolean authenticate(String username, String password) throws LoginException {
        if (!userFile.exists()) {
            logger.error("XmlUsersFile not found: {}", userFile.getAbsolutePath());
            return false;
        }

        try {
            refreshUsers();
        }
        catch (Exception e) {
            throw new LoginException("Failed to parse user file.");
        }
        FullUserInfo fullUser = users.get(new User(username, password));
        if (fullUser == null) {
            if (logger.isDebugEnabled()) {
                logger.debug("Credentials not matched from XmlUsersFile.");
            }
            return false;
        }

        principal = new UserPrincipal();
        attributes = fullUser.attributes;
        return true;
    }

    protected static File getUsersFile() {
        if (userFile == null) {
            synchronized (XmlUsersFileModule.class) {
                if (Constants.FEDORA_HOME == null || "".equals(Constants.FEDORA_HOME)) {
                    logger.error("FEDORA_HOME constant is not set");
                }
                else {
                    if (logger.isDebugEnabled()) {
                        logger.debug("using FEDORA_HOME: " + Constants.FEDORA_HOME);
                    }
                }
                userFile = new File(Constants.FEDORA_HOME + "/server/config/fedora-users.xml");
            }
        }

        return userFile;
    }

    protected Document getUserDocument() throws IOException {
        try {
            final Document userDoc = DataUtils.getDocumentFromFile(userFile);
            userFileParsed = userFile.lastModified();
            userFileBytesLoaded = userFile.length();

            return userDoc;
        }
        catch (Exception e) {
            throw new IOException("Failed to parse user mapping.", e);
        }
    }

    /**
     * Re-parse the users if necessary.
     *
     * @throws IOException
     */
    protected void refreshUsers() throws IOException {
        if (users == null || userFileParsed != userFile.lastModified() || userFileBytesLoaded != userFile.length()) {
            synchronized (XmlUsersFileModule.class) {
                if (users == null || userFileParsed != userFile.lastModified()
                        || userFileBytesLoaded != userFile.length()) {
                    users = parseUsers();
                }
            }
        }
    }

    /**
     * Parse the document users.
     *
     * @return A(n unmodifiable) map of users.
     * @throws IOException
     */
    protected Map<User, FullUserInfo> parseUsers() throws IOException {
        final Map<User, FullUserInfo> users = new HashMap<User, FullUserInfo>();

        final Document userDoc = getUserDocument();
        // go through each user
        final NodeList userList = userDoc.getElementsByTagName("user");
        for (int x = 0; x < userList.getLength(); x++) {
            final Element user_el = (Element) userList.item(x);

            final String name = user_el.getAttribute("name");
            final String password = user_el.getAttribute("password");
            final Map<String, Set<String>> attributes = new HashMap<String, Set<String>>();

            // for a matched user, go through each attribute
            final NodeList attributeList = user_el.getElementsByTagName("attribute");
            for (int y = 0; y < attributeList.getLength(); y++) {
                final Element attribute = (Element) attributeList.item(y);
                final String attribute_name = attribute.getAttribute("name");

                // go through each value
                final NodeList valueList =
                        attribute.getElementsByTagName("value");
                for (int z = 0; z < valueList.getLength(); z++) {
                    final Element value = (Element) valueList.item(z);
                    final String v = value.getFirstChild().getNodeValue();

                    Set<String> values = attributes.get(attribute_name);
                    if (values == null) {
                        values = new HashSet<String>();
                        attributes.put(attribute_name, values);
                    }

                    values.add(v);
                }
            }
            final FullUserInfo user = new FullUserInfo(name, password, attributes);
            if (!users.containsKey(user)) {
                // Upstream class would use the _first_ matching user it finds,
                // so let's make sure not to replace users already there.
                users.put(user, user);
            }
        }

        return Collections.unmodifiableMap(users);
    }

    protected static class User {
        protected String name;
        protected String password;

        public User(String name, String password) {
            this.name = name;
            this.password = password;
        }

        @Override
        public int hashCode() {
            return name.hashCode() + password.hashCode();
        }

        @Override
        public boolean equals(final Object o) {
            if (!(o instanceof User)) {
                return false;
            }
            final User other = (User) o;
            return name.equals(other.name) && password.equals(other.password);
        }
    }

    protected static class FullUserInfo extends User {
        final protected Map<String, Set<String>> attributes;

        public FullUserInfo(String name, String password, final Map<String, Set<String>> attributes) {
            super(name, password);
            this.attributes = attributes;
        }
    }
}
