package ch.bfh.ti.saml.config;

import org.opensaml.DefaultBootstrap;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.UnmarshallerFactory;

/**
 *
 * @author admin
 */
public class Config {

    private static XMLObjectBuilderFactory xmlObjectBuilderFactory;
    private static UnmarshallerFactory unmarshallerFactory;
    private static MarshallerFactory marshallerFactory;
    private static boolean isInitialized;

    public void initialize() {
        try {
            if (!isInitialized) {
                DefaultBootstrap.bootstrap();
                xmlObjectBuilderFactory = Configuration.getBuilderFactory();
                unmarshallerFactory = Configuration.getUnmarshallerFactory();
                marshallerFactory = Configuration.getMarshallerFactory();
                isInitialized = true;
            }
        } catch (ConfigurationException ex){
            //TODO logger
        }

    }

    public static XMLObjectBuilderFactory getXmlObjectBuilderFactory() {
        return xmlObjectBuilderFactory;
    }

    public static UnmarshallerFactory getUnmarshallerFactory() {
        return unmarshallerFactory;
    }

    public static MarshallerFactory getMarshallerFactory() {
        return marshallerFactory;
    }

}
