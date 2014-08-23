package ch.bfh.ti.saml.util;

import ch.bfh.ti.saml.config.Config;
import java.io.InputStream;
import javax.xml.namespace.QName;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 *
 * @author admin
 */
public class SamlUtil {

    /**
     *
     * @param qname
     * @return
     */
    public static XMLObject createXMLObject(QName qname) {
        XMLObjectBuilderFactory builderFactory = Config.getXmlObjectBuilderFactory();
        XMLObjectBuilder<?> builder = (XMLObjectBuilder<?>) builderFactory.getBuilder(qname);
        return builder.buildObject(qname);
    }

    /**
     *
     * @param xmlSource
     * @return
     * @throws XMLParserException
     * @throws UnmarshallingException
     */
    public static EntityDescriptor getEntityDecriptor(String xmlSource) throws XMLParserException, UnmarshallingException {

        // Get parser pool manager
        BasicParserPool ppMgr = new BasicParserPool();
        ppMgr.setNamespaceAware(true);

        // Parse metadata file
        InputStream in = SamlUtil.class.getResourceAsStream(xmlSource);
        Document inCommonMDDoc = ppMgr.parse(in);
        Element metadataRoot = inCommonMDDoc.getDocumentElement();

        // Unmarshall using the document root element, an EntityDescriptor in this case
        return (EntityDescriptor)unmarshall(metadataRoot);
    }
    

    /**
     * 
     * @param element
     * @return
     * @throws UnmarshallingException 
     */
    public static XMLObject unmarshall(Element element) throws UnmarshallingException {
       return Config.getUnmarshallerFactory().getUnmarshaller(element).unmarshall(element);
    }

    /**
     * 
     * @param xmlObject
     * @return
     * @throws MarshallingException 
     */
    public static Element marshall(XMLObject xmlObject) throws MarshallingException {
       return Config.getMarshallerFactory().getMarshaller(xmlObject).marshall(xmlObject);
    }
}
