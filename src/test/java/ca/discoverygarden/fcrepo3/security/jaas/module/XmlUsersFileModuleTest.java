package ca.discoverygarden.fcrepo3.security.jaas.module;

import java.io.File;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;

import junit.framework.TestCase;

public class XmlUsersFileModuleTest extends TestCase {
    protected XmlUsersFileModule module;

    @SuppressWarnings({
        "unchecked", "rawtypes"
    })
    @Override
    protected void setUp() throws Exception {
        super.setUp();
        XmlUsersFileModule.userFile = new File(XmlUsersFileModule.class.getResource("/fedora-users.xml").toURI());

        module = new XmlUsersFileModule();
        module.initialize(new Subject(), null, new HashMap(), new HashMap());
    }

    public void testParse() throws LoginException {
        assertTrue(module.authenticate("fedoraAdmin", "test_password"));

        final Map<String, Set<String>> attributes = module.attributes;

        assertTrue(attributes.containsKey("fedoraRole"));
        final Set<String> roles = attributes.get("fedoraRole");
        assertTrue(roles.contains("administrator"));
        assertFalse(roles.contains("authenticated user"));
        assertFalse(attributes.containsKey("roles"));

        assertTrue(attributes.containsKey("custom_one"));
        final Set<String> c1 = attributes.get("custom_one");
        assertTrue(c1.contains("custom one"));
        assertTrue(c1.contains("one custom"));
        assertFalse(c1.contains("bravo"));

        assertTrue(attributes.containsKey("custom_two"));
        assertTrue(attributes.get("custom_two").contains("bravo"));
        assertFalse(attributes.get("custom_two").contains("custom one"));
    }

    public void testParseTwo() throws LoginException {
        assertTrue(module.authenticate("fedoraIntCallUser", "test_changeme"));

        final Map<String, Set<String>> attributes = module.attributes;

        assertTrue(attributes.containsKey("fedoraRole"));
        final Set<String> roles = attributes.get("fedoraRole");
        assertTrue(roles.contains("fedoraInternalCall-1"));
        assertTrue(roles.contains("fedoraInternalCall-2"));
        assertFalse(roles.contains("administrator"));

        assertFalse(attributes.containsKey("custom_one"));
    }
}
