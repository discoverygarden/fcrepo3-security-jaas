package ca.discoverygarden.fcrepo3.security.jaas.module;

import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.dom4j.DocumentException;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

public class DrupalMultisiteAuthModuleTest {
    protected DrupalMultisiteAuthModuleMock mockInstance;
    protected final String KEY = "test_key";

    @Before
    public void setUp() throws Exception {
        mockInstance = new DrupalMultisiteAuthModuleMock();
    };

    @BeforeClass
    public static void isSqlEnabled() {
        assumeTrue("SQL Tests are enabled.", System.getProperty("skipSqlTests", "true").equals("false"));
    }

    @SuppressWarnings({
        "unchecked", "rawtypes"
    })
    protected Set<String> findRoles(String name, String pass) {
        mockInstance.initialize(new Subject(), new MockHandler(), new HashMap(), new HashMap());
        mockInstance.findUser(name, pass, KEY);
        assertTrue("Found user.", mockInstance.getSuccess());
        return mockInstance.getAttributes().get("role");
    }

    @Test
    public void testFindUserUserOneHasAdministratorRole() {
        Set<String> roles = findRoles("alpha", "first");
        assertTrue("User \"1\" gets the \"administrator\" role", roles.contains("administrator"));
    }

    @Test
    public void testFindUserAnonymous() {
        Set<String> roles = findRoles("anonymous", "anonymous");
        assertTrue("Anonymous gets the anonymous role",
                roles.contains(DrupalMultisiteAuthModuleMock.getAnonymousRole()));
    }

    @Test
    @SuppressWarnings({
        "rawtypes", "unchecked"
    })
    public void testFindUserAuthenticatedUser() throws IOException, DocumentException {
        Map<String, String> users = new HashMap<String, String>();
        users.put("alpha", "first");
        users.put("bravo", "second");
        users.put("charlie", "third");

        for (String key : users.keySet()) {
            mockInstance = new DrupalMultisiteAuthModuleMock();
            Set<String> roles = findRoles(key, users.get(key));
            assertTrue(roles.contains("authenticated user"));
        }
    }

    @Test
    public void testFindUserAlphaConfiguredRoles() {
        Set<String> roles = findRoles("alpha", "first");
        assertTrue("Alpha has proper roles", (roles.contains("authenticated user") && roles.contains("first role")
                && roles.contains("second role") && roles.contains("third role")));
    }

    @Test
    public void testFindUserBravoConfiguredRoles() {
        Set<String> roles = findRoles("bravo", "second");
        assertTrue("Bravo has proper roles", (roles.contains("authenticated user") && !roles.contains("first role")
                && roles.contains("second role") && !roles.contains("third role")));
    }

    @Test
    public void testFindUserCharlieConfiguredRoles() {
        Set<String> roles = findRoles("charlie", "third");
        assertTrue("Charlie has proper roles", (roles.contains("authenticated user") && !roles.contains("first role")
                && !roles.contains("second role") && !roles.contains("third role")));
    }

    private class MockHandler implements CallbackHandler {
        @Override
        public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
            // No-op
        }
    }
}
