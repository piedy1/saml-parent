package ch.bfh.ti.saml.util;

import ch.bfh.ti.saml.config.Config;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.apache.log4j.Logger;
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
        
     private static final Logger logger = Logger.getLogger(SamlUtil.class.getName());
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
     * @param xmlSourcePath
     * @return
     * @throws XMLParserException
     * @throws UnmarshallingException //TODO analyze this method
     * @throws java.io.FileNotFoundException
     */
    public static XMLObject createXMLObjectFromXMLSource(String xmlSourcePath) throws XMLParserException, UnmarshallingException, FileNotFoundException {
        
        // Get parser pool manager
        BasicParserPool ppMgr = new BasicParserPool();
        ppMgr.setNamespaceAware(true);

        // Parse metadata file
        logger.debug("Loading XML Object from source: "+xmlSourcePath);
        InputStream in = new FileInputStream(xmlSourcePath);
        Document inCommonMDDoc = ppMgr.parse(in);
        Element metadataRoot = inCommonMDDoc.getDocumentElement();

        // Unmarshall using the document root element, an EntityDescriptor in this case
        return unmarshall(metadataRoot);
    }

    /**
     *
     * @param outputXmlPath
     * @param xmlObj
     */
    public static void writeXMLObjectToXML(String outputXmlPath, XMLObject xmlObj) {
        try {

            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document document = builder.newDocument();

            logger.debug("Writing XML Object to source: "+outputXmlPath);
            OutputStream os = new FileOutputStream(outputXmlPath);

            marshall(xmlObj, document);

            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer trans = tf.newTransformer();
            trans.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
//          The code below invalidate the signature
//          trans.setOutputProperty(OutputKeys.INDENT, "yes");
//          trans.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
            
            trans.transform(new DOMSource(document), new StreamResult(os));
            logger.info("XML Object writed succesfully to source: "+outputXmlPath);
          
        } catch (MarshallingException | ParserConfigurationException | TransformerConfigurationException ex) {
            logger.error("Error writing XML object to source: ", ex);
        } catch (TransformerException | IOException ex) {
            logger.error("Error writing XML object to source: ", ex);
        }
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

    /**
     *
     * @param xmlObject
     * @param document
     * @return
     * @throws MarshallingException
     */
    public static Element marshall(XMLObject xmlObject, Document document) throws MarshallingException {
        return Config.getMarshallerFactory().getMarshaller(xmlObject).marshall(xmlObject, document);
    }
}
