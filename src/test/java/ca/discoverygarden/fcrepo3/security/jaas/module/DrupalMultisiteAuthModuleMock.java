package ca.discoverygarden.fcrepo3.security.jaas.module;

import java.io.IOException;
import java.util.Map;
import java.util.Set;

import org.dom4j.Document;
import org.dom4j.DocumentException;

public class DrupalMultisiteAuthModuleMock extends DrupalMultisiteAuthModule {
    public DrupalMultisiteAuthModuleMock() throws IOException, DocumentException {
        super();
    }

    @Override
    protected void parseConfig() throws DocumentException, IOException {
        Document doc = getParsedConfig(this.getClass().getResourceAsStream("/filter-drupal-multisite.xml"));
        parseConfig(doc);
    }

    protected Map<String, Set<String>> getAttributes() {
        return attributes;
    }

    protected static String getAnonymousRole() {
        return DrupalMultisiteAuthModuleMock.ANONYMOUSROLE;
    }

    protected boolean getSuccess() {
        return successLogin;
    }
}
