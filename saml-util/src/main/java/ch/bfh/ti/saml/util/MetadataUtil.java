/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ch.bfh.ti.saml.util;

import ch.bfh.ti.saml.common.OrganizationCharacteristic;
import ch.bfh.ti.saml.config.Config;
import static ch.bfh.ti.saml.util.SamlUtil.unmarshall;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;
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
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.AttributeConsumingService;
import org.opensaml.saml2.metadata.ContactPerson;
import org.opensaml.saml2.metadata.ContactPersonTypeEnumeration;
import org.opensaml.saml2.metadata.EmailAddress;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.GivenName;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml2.metadata.LocalizedString;
import org.opensaml.saml2.metadata.NameIDFormat;
import org.opensaml.saml2.metadata.Organization;
import org.opensaml.saml2.metadata.OrganizationDisplayName;
import org.opensaml.saml2.metadata.OrganizationName;
import org.opensaml.saml2.metadata.OrganizationURL;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml2.metadata.SurName;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.security.SecurityConfiguration;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 *
 * @author Yandy
 */
public class MetadataUtil {

//            TODO
//            <element ref="md:RoleDescriptor"/>
//            <element ref="md:IDPSSODescriptor"/>
//            <element ref="md:AuthnAuthorityDescriptor"/>
//            <element ref="md:AttributeAuthorityDescriptor"/>
//            <element ref="md:PDPDescriptor"/> 
//    <md:SPSSODescriptor
//    protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
//    <md:KeyDescriptor use="signing">
//      <ds:KeyInfo>
//        <ds:KeyName>SP SSO Key</ds:KeyName>
//      </ds:KeyInfo>
//    </md:KeyDescriptor>
//    <md:ArtifactResolutionService isDefault="true" index="0"
//      Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP"
//      Location="https://sp.example.com/SAML2/ArtifactResolution"/>
//    <md:NameIDFormat>
//      urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress
//    </md:NameIDFormat>
//    <md:NameIDFormat>
//      urn:oasis:names:tc:SAML:2.0:nameid-format:transient
//    </md:NameIDFormat>
//    <md:AssertionConsumerService isDefault="true" index="0"
//      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
//      Location="https://sp.example.com/SAML2/SSO/POST"/>
//    <md:AssertionConsumerService index="1"
//      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"
//      Location="https://sp.example.com/SAML2/Artifact"/>
//    <md:AttributeConsumingService isDefault="true" index="1">
//      <md:ServiceName xml:lang="en">
//        Service Provider Portal
//      </md:ServiceName>
//      <md:RequestedAttribute
//        NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
//        Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.1"
//        FriendlyName="eduPersonAffiliation">
//      </md:RequestedAttribute>
//    </md:AttributeConsumingService>
//  </md:SPSSODescriptor>
    /**
     *
     * @param entityId
     * @param spSSODesc
     * @param org
     * @param contactPerson
     * @return 
     */
    public static EntityDescriptor generateSPEntityDescriptor(String entityId, SPSSODescriptor spSSODesc, Organization org, List<ContactPerson>contactPerson) {
        EntityDescriptor entityDec = (EntityDescriptor) SamlUtil.createXMLObject(EntityDescriptor.DEFAULT_ELEMENT_NAME);
        entityDec.setEntityID(entityId);
        entityDec.setID("_"+UUID.randomUUID().toString());
        entityDec.getRoleDescriptors().add(spSSODesc);
        entityDec.setOrganization(org);
        for(ContactPerson cp : contactPerson)
            entityDec.getContactPersons().add(cp);
        return entityDec;
    }

    /**
     *
     * @param isAuthRequestSigned
     * @param wantAssertionsSigned
     * @param keyDes
     * @param sigLogouts
     * @param nameIds
     * @param assertConsServs
     * @param attributeConServ //TODO attributeConServ
     * @return
     */
    public static SPSSODescriptor genarateSPSSODescriptor(boolean isAuthRequestSigned, boolean wantAssertionsSigned, List<KeyDescriptor> keyDes,
        List<SingleLogoutService> sigLogouts, List<NameIDFormat> nameIds,
        List<AssertionConsumerService> assertConsServs, AttributeConsumingService attributeConServ) {
        SPSSODescriptor spSSODesc = (SPSSODescriptor) SamlUtil.createXMLObject(SPSSODescriptor.DEFAULT_ELEMENT_NAME);
        spSSODesc.addSupportedProtocol(SAMLConstants.SAML20P_NS);
        spSSODesc.setAuthnRequestsSigned(isAuthRequestSigned);
        spSSODesc.setWantAssertionsSigned(wantAssertionsSigned);

        for (KeyDescriptor key : keyDes) {
            spSSODesc.getKeyDescriptors().add(key);
        }

        for (SingleLogoutService sls : sigLogouts) {
            spSSODesc.getSingleLogoutServices().add(sls);
        }

        for (NameIDFormat nameID : nameIds) {
            spSSODesc.getNameIDFormats().add(nameID);
        }

        for (AssertionConsumerService asserSev : assertConsServs) {
            spSSODesc.getAssertionConsumerServices().add(asserSev);
        }

        return spSSODesc;
    }

    /**
     *
     * @param useType
     * @param keyInfo
     * @return
     */
    public static KeyDescriptor generateKeyDescriptor(UsageType useType, KeyInfo keyInfo) {
        KeyDescriptor keyDesc = (KeyDescriptor) SamlUtil.createXMLObject(KeyDescriptor.DEFAULT_ELEMENT_NAME);
        keyDesc.setUse(useType);
        keyDesc.setKeyInfo(keyInfo);
        return keyDesc;
    }

    /**
     *
     * @param binding
     * @param location
     * @return
     */
    public static SingleLogoutService generateSingleLogoutService(String binding, String location) {
        SingleLogoutService singleLogout = (SingleLogoutService) SamlUtil.createXMLObject(SingleLogoutService.DEFAULT_ELEMENT_NAME);
        singleLogout.setBinding(binding);
        singleLogout.setLocation(location);
        return singleLogout;
    }

    /**
     *
     * @param format
     * @return
     */
    public static NameIDFormat generateNameIDFormat(String format) {
        NameIDFormat nameIdFormat = (NameIDFormat) SamlUtil.createXMLObject(NameIDFormat.DEFAULT_ELEMENT_NAME);
        nameIdFormat.setFormat(format);
        return nameIdFormat;
    }

    /**
     *
     * @param index
     * @param isDefault
     * @param binding
     * @param location
     * @return
     */
    public static AssertionConsumerService generateAssertionConsumerService(int index, boolean isDefault, String binding, String location) {
        AssertionConsumerService asserConsumServ = (AssertionConsumerService) SamlUtil.createXMLObject(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
        asserConsumServ.setIsDefault(isDefault);
        asserConsumServ.setIndex(index);
        asserConsumServ.setBinding(binding);
        asserConsumServ.setLocation(location);
        return asserConsumServ;
    }

    /**
     *
     * @param orgCharact
     * @return
     */
    public static Organization genarateOrganization(List<OrganizationCharacteristic> orgCharact) {
        Organization organization = (Organization) SamlUtil.createXMLObject(Organization.DEFAULT_ELEMENT_NAME);
        for (OrganizationCharacteristic orgChar : orgCharact) {
            organization.getDisplayNames().add(orgChar.getOrgDisName());
            organization.getOrganizationNames().add(orgChar.getOrgName());
            organization.getURLs().add(orgChar.getOrgUrl());
        }
        return organization;
    }

    /**
     *
     * @param orgDisplayName
     * @return
     */
    public static OrganizationDisplayName genarateOrganizationDisplayName(LocalizedString orgDisplayName) {
        OrganizationDisplayName orgDisplayN = (OrganizationDisplayName) SamlUtil.createXMLObject(OrganizationDisplayName.DEFAULT_ELEMENT_NAME);
        orgDisplayN.setName(orgDisplayName);
        return orgDisplayN;
    }

    /**
     *
     * @param orgName
     * @return
     */
    public static OrganizationName genarateOrganizationName(LocalizedString orgName) {
        OrganizationName orgN = (OrganizationName) SamlUtil.createXMLObject(OrganizationName.DEFAULT_ELEMENT_NAME);
        orgN.setName(orgName);
        return orgN;
    }

    /**
     *
     * @param orgURL
     * @return
     */
    public static OrganizationURL genarateOrganizationURL(LocalizedString orgURL) {
        OrganizationURL orgUrl = (OrganizationURL) SamlUtil.createXMLObject(OrganizationURL.DEFAULT_ELEMENT_NAME);
        orgUrl.setURL(orgURL);
        return orgUrl;
    }

    /**
     *
     * @param contactType
     * @param name
     * @param surname
     * @param emailAddress
     * @return
     */
    public static ContactPerson genarateContactPerson(ContactPersonTypeEnumeration contactType, GivenName name, SurName surname,
            List<EmailAddress> emailAddress) {
        ContactPerson contactPerson = (ContactPerson) SamlUtil.createXMLObject(ContactPerson.DEFAULT_ELEMENT_NAME);
        contactPerson.setType(contactType);
        contactPerson.setGivenName(name);
        contactPerson.setSurName(surname);
        for (EmailAddress email : emailAddress) {
            contactPerson.getEmailAddresses().add(email);
        }
        return contactPerson;
    }

    public static void main(String[] args) throws XMLParserException, FileNotFoundException, UnmarshallingException {
        Config conf = new Config();
        conf.initialize();

        NameIDFormat nameIdFor = generateNameIDFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:transient");
        List<NameIDFormat> nameIdsForm = new ArrayList<>();
        nameIdsForm.add(nameIdFor);
            
        SPSSODescriptor sp = genarateSPSSODescriptor(true, true, new ArrayList<KeyDescriptor>(),
                new ArrayList<SingleLogoutService>(), nameIdsForm ,
                new ArrayList<AssertionConsumerService>(), null);

//        EntityDescriptor ent = generateSPEntityDescriptor("https://sp.bfh.ch", sp, null, new ArrayList<ContactPerson>());
        
        AuthnRequest r = (AuthnRequest) SamlUtil.createXMLObjectFromXMLSource("C:\\Users\\admin\\Desktop\\SuisseID_2.0\\SuisseID_2.0\\ClaimAssertionService\\trunk\\ClaimAssertionService\\src\\test\\resources\\requestToSign.xml");
        
        try {
            
            KeyStore.PrivateKeyEntry entry = SignatureUtil.getKeyStore("C:\\Users\\admin\\Desktop\\myidp.jks", "moleson", "tomcat", "moleson");
            SignatureUtil.SignSignableSAMLObject(r, entry);
            
            SamlUtil.writeXMLObjectToXML("src/main/resources/metadata/sp-metadata.xml", r);
            
        }     
        catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException | UnrecoverableEntryException ex) {
            Logger.getLogger(MetadataUtil.class.getName()).log(Level.SEVERE, null, ex);
        }
       
        try {
//            EntityDescriptor ent1 = (EntityDescriptor) SamlUtil.createXMLObjectFromXMLSource("src/main/resources/metadata/sp-metadata.xml");
             AuthnRequest r2 = (AuthnRequest) SamlUtil.createXMLObjectFromXMLSource("src/main/resources/metadata/sp-metadata.xml");
            
//             if(r2.equals(r)){
//                 System.out.println("They are equals!");
//             }
//             else
//                 System.out.println("They are not equals!");
//             
             if (SignatureUtil.istSignatureValid(r2)) {
                System.out.println("The signature is valid");
            } else {
                System.out.println("The signature is not valid");
            }
        } catch (Exception ex) {
            System.err.println("Could not create EntityDescriptor");
        }
        

    }

}
