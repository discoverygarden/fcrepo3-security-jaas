package ca.discoverygarden.fcrepo3.security.jaas.module;

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.CredentialNotFoundException;
import javax.security.auth.login.LoginException;

import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.Element;

import ca.discoverygarden.fcrepo3.security.jaas.filter.KeyChoiceCallback;
import ca.discoverygarden.fcrepo3.security.jaas.filter.MissingCredsException;
import ca.discoverygarden.fcrepo3.security.jaas.filter.UpstreamAuthFilterJAAS;
import ca.upei.roblib.fedora.servletfilter.DrupalAuthModule;

public class DrupalMultisiteAuthModule extends DrupalAuthModule {
    /**
     * The name of the attribute we are to make available (in XACML).
     */
    public static final String SUBJECT_AGENT_ATTRIBUTE_NAME = "islandora-agent";

    /**
     * The name of the column containing the userid.
     */
    public static final String SQL_COL_ID = "userid";
    /**
     * The name of the column containing the roles.
     */
    public static final String SQL_COL_ROLE = "role";

    /**
     * The key in the parsed map containing the sql query.
     */
    public static final String XML_SQL_ELEMENT_NAME = "sql";

    /**
     * The string, "anonymous".
     */
    public static final String ANONYMOUS = "anonymous";

    protected Map<String, Map<String, String>> config;

    public DrupalMultisiteAuthModule() throws IOException, DocumentException {
        config = new HashMap<String, Map<String, String>>();
        parseConfig();
    }
    
    /**
     * Parse connection entries from the default document.
     * @throws DocumentException
     * @throws IOException
     */

    protected void parseConfig() throws DocumentException, IOException {
        Document doc = getParsedConfig();
        parseConfig(doc);
    }
    
    /**
     * Parse connection entries out of the given document.
     * @param doc
     */

    protected void parseConfig(Document doc) {
        config.clear();
        @SuppressWarnings("unchecked")
        List<Element> list = doc.selectNodes("//FilterDrupal_Connection/connection[@key]");
        for (Element el : list) {
            config.put(el.attributeValue("key").trim(), parseConnectionElement(el));
        }
    }


    @Override
    public boolean login() throws LoginException {
        if (debug) {
            logger.debug(String.format("%s login called.", DrupalMultisiteAuthModule.class.getName()));
            for (String key : sharedState.keySet()) {
                String value = sharedState.get(key).toString();
                logger.debug(key + ": " + value);
            }
        }

        String[] keys = config.keySet().toArray(new String[0]);
        NameCallback nc = new NameCallback("username");
        PasswordCallback pc = new PasswordCallback("password", false);
        KeyChoiceCallback kcc = new KeyChoiceCallback(keys);
        Callback[] callbacks = new Callback[] {
                nc, pc, kcc
        };

        try {
            handler.handle(callbacks);
            username = nc.getName();
            char[] passwordCharArray = pc.getPassword();
            String password = new String(passwordCharArray);
            int[] key_selections = kcc.getSelectedIndexes();

            // Should only be exactly one item in key_selections; however,
            // let's iterate for brevity.
            for (int i : key_selections) {
                findUser(username, password, keys[i]);
            }

        }
        catch (IOException ioe) {
            ioe.printStackTrace();
            throw new LoginException("IOException occured: " + ioe.getMessage());
        }
        catch (MissingCredsException mce) {
            throw new CredentialNotFoundException(
                    String.format("Missing \"key\", required for module %s.", this.getClass().getName()));
        }
        catch (UnsupportedCallbackException ucbe) {
            throw new LoginException("UnsupportedCallbackException: " + ucbe.getMessage());
        }

        return successLogin;
    }

    /**
     * Helper to set our agent attribute for XACML.
     *
     * @param agent
     *            Our site-specific key.
     */

    protected void setAgentsSet(String agent) {
        Set<String> agents = new HashSet<String>();
        agents.add(agent);
        attributes.put(SUBJECT_AGENT_ATTRIBUTE_NAME, agents);
    }


    /**
     * Find the given user.
     *
     * @see DrupalAuthModule.findUser()
     *
     * @param userid
     *            The user to authenticate.
     * @param password
     *            The password with which to authenticate.
     * @param agent
     *            The site-specific key to identify where to search.
     */
    protected void findUser(String userid, String password, String agent) {
        if (logger.isDebugEnabled()) {
            logger.debug(String.format("Attempting to find %s against %s", userid, agent));
        }
        setAgentsSet(agent);

        // If the user is anonymous don't check the database just give the
        // anonymous role.
        if (ANONYMOUS.equals(userid) && ANONYMOUS.equals(password)) {
            createAnonymousUser();
            return;
        }

        Set<String> roles = new HashSet<String>();

        try {
            Map<String, String> parsed = config.get(agent);

            // XXX: We may want to implement some form of connection pooling.
            Connection conn = connectToDB(parsed);
            if (conn != null) {
                PreparedStatement pstmt = conn.prepareStatement(parsed.get(XML_SQL_ELEMENT_NAME));
                pstmt.setString(2, password);
                pstmt.setString(1, userid);
                ResultSet rs = pstmt.executeQuery();
                boolean hasMoreRecords = rs.next();
                if (hasMoreRecords && roles.isEmpty()) {
                    username = userid;
                    switch (rs.getInt(SQL_COL_ID)) {
                        case 0:
                            // XXX: Just here for completeness... Really, this
                            // code should never be hit.
                            logger.warn("Got login for user with ID 0.");
                            roles.add(DrupalAuthModule.ANONYMOUSROLE);
                            // XXX: Maintain old "anonymous" role, in case it is
                            // actually being used.
                            roles.add(ANONYMOUS);
                            break;
                        case 1:
                            roles.add("administrator");
                            // Fallthrough
                        default:
                            roles.add("authenticated user");
                    }
                    successLogin = true;
                }
                while (hasMoreRecords) {
                    String role = rs.getString(SQL_COL_ROLE);
                    if (role != null) {
                        logger.debug(
                                String.format("%s, added role: %s", DrupalMultisiteAuthModule.class.getName(), role));
                        roles.add(role);
                    }
                    hasMoreRecords = rs.next();
                }
                conn.close();
            }
            else if (logger.isDebugEnabled()) {
                logger.debug(String.format("Failed to connect to DB for %s.", agent));
            }
        }
        catch (SQLException ex) {
            logger.error("Error retrieving user info " + ex.getMessage());
        }

        attributes.put(UpstreamAuthFilterJAAS.ROLE_KEY, roles);
    }
}
