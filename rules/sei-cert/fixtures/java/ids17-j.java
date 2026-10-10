// SEI CERT IDS17-J focused fixture.
import java.io.InputStream;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import org.xml.sax.SAXException;

class XmlReaders {
    DocumentBuilder documents() throws ParserConfigurationException, SAXException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setExpandEntityReferences(true);
        // cert: positive appsec-review.sei-cert.java.ids17-j.parser-without-entity-restriction
        return factory.newDocumentBuilder();
    }

    SAXParser events() throws ParserConfigurationException, SAXException {
        SAXParserFactory factory = SAXParserFactory.newInstance();
        factory.setNamespaceAware(true);
        // cert: variant appsec-review.sei-cert.java.ids17-j.parser-without-entity-restriction
        return factory.newSAXParser();
    }

    DocumentBuilder hardened() throws ParserConfigurationException, SAXException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        // cert: safe-alternative appsec-review.sei-cert.java.ids17-j.parser-without-entity-restriction
        return factory.newDocumentBuilder();
    }

    SAXParser noExternalEntities() throws ParserConfigurationException, SAXException {
        SAXParserFactory factory = SAXParserFactory.newInstance();
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        // cert: negative appsec-review.sei-cert.java.ids17-j.parser-without-entity-restriction
        return factory.newSAXParser();
    }

    DocumentBuilder fromField(DocumentBuilderFactory configured) throws ParserConfigurationException, SAXException {
        // cert: near-miss appsec-review.sei-cert.java.ids17-j.parser-without-entity-restriction
        return configured.newDocumentBuilder();
    }
}
