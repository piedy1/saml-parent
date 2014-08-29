/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ch.bfh.ti.saml.util;

import ch.bfh.ti.saml.common.OrganizationCharacteristic;
import ch.bfh.ti.saml.config.Config;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.AbstractList;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.xml.security.utils.EncryptionConstants;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.AttributeConsumingService;
import org.opensaml.saml2.metadata.ContactPerson;
import org.opensaml.saml2.metadata.ContactPersonTypeEnumeration;
import org.opensaml.saml2.metadata.EmailAddress;
import org.opensaml.saml2.metadata.EncryptionMethod;
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
import org.opensaml.xml.encryption.DecryptionException;
import org.opensaml.xml.encryption.EncryptionException;
import org.opensaml.xml.encryption.KeySize;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.security.credential.BasicCredential;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;
import sun.security.krb5.internal.CredentialsUtil;

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
    public static EntityDescriptor generateSPEntityDescriptor(String entityId, SPSSODescriptor spSSODesc, Organization org, List<ContactPerson> contactPerson) {
        EntityDescriptor entityDec = (EntityDescriptor) SamlUtil.createXMLObject(EntityDescriptor.DEFAULT_ELEMENT_NAME);
        entityDec.setEntityID(entityId);
        entityDec.setID("_" + UUID.randomUUID().toString());
        entityDec.getRoleDescriptors().add(spSSODesc);
        entityDec.setOrganization(org);
        for (ContactPerson cp : contactPerson) {
            entityDec.getContactPersons().add(cp);
        }
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
     * @param keyInfo
     * @return
     */
    public static KeyDescriptor generateKeyDescriptorSigning(KeyInfo keyInfo) {
        KeyDescriptor keySign = (KeyDescriptor) SamlUtil.createXMLObject(KeyDescriptor.DEFAULT_ELEMENT_NAME);
        keySign.setUse(UsageType.SIGNING);
        keySign.setKeyInfo(keyInfo);
        return keySign;
    }

    /**
     *
     * @param keyInfo
     * @param encMethods
     * @return
     */
    public static KeyDescriptor generateKeyDescriptorEncryption(KeyInfo keyInfo, List<EncryptionMethod> encMethods) {
        KeyDescriptor keyDesc = (KeyDescriptor) SamlUtil.createXMLObject(KeyDescriptor.DEFAULT_ELEMENT_NAME);
        keyDesc.setUse(UsageType.ENCRYPTION);
        keyDesc.setKeyInfo(keyInfo);
        for (EncryptionMethod enM : encMethods) {
            keyDesc.getEncryptionMethods().add(enM);
        }
        return keyDesc;
    }

    /**
     *
     * @param encryptionAlgorithm
     * @param keySize
     * @return
     */
    public static EncryptionMethod generateEncryptionMethod(String encryptionAlgorithm, int keySize) {
        EncryptionMethod encry = (EncryptionMethod) SamlUtil.createXMLObject(EncryptionMethod.DEFAULT_ELEMENT_NAME);
        encry.setAlgorithm(encryptionAlgorithm);
        KeySize ks = (KeySize) SamlUtil.createXMLObject(KeySize.DEFAULT_ELEMENT_NAME);
        ks.setValue(keySize);
        encry.setKeySize(ks);
        return encry;
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

    public static void main(String[] args) throws XMLParserException, FileNotFoundException, UnmarshallingException, KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, UnrecoverableEntryException, EncryptionException {
        Config conf = new Config();
        conf.initialize();

        try {
            KeyStore.PrivateKeyEntry entry = CertificateUtil.getKeyStore("/Users/Yandy/Desktop/myidp.jks", "moleson", "tomcat", "moleson");
            BasicX509Credential credential = CertificateUtil.getSigningCredential(entry);
            KeyInfo keyInfo = CertificateUtil.getKeyInfo(credential);

            EncryptionMethod encMethod = MetadataUtil.generateEncryptionMethod(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128, 128);

            List<EncryptionMethod> encMethods = new ArrayList<>();
            encMethods.add(encMethod);

            //You must create a new keyInfo
            KeyStore.PrivateKeyEntry entry1 = CertificateUtil.getKeyStore("/Users/Yandy/Desktop/myidp.jks", "moleson", "tomcat", "moleson");
            BasicX509Credential credential1 = CertificateUtil.getSigningCredential(entry1);
            KeyInfo keyInfo1 = CertificateUtil.getKeyInfo(credential1);

            KeyDescriptor keySign = MetadataUtil.generateKeyDescriptorSigning(keyInfo);
            KeyDescriptor keyEncrypt = MetadataUtil.generateKeyDescriptorEncryption(keyInfo1, encMethods);

            List<KeyDescriptor> keysDecryptor = new ArrayList<>();
            keysDecryptor.add(keySign);
            keysDecryptor.add(keyEncrypt);

            NameIDFormat nameIdFor = generateNameIDFormat(NameIDType.TRANSIENT);
            List<NameIDFormat> nameIdsForm = new ArrayList<>();
            nameIdsForm.add(nameIdFor);

            SPSSODescriptor sp = genarateSPSSODescriptor(true, true, keysDecryptor,
                    new ArrayList<SingleLogoutService>(), nameIdsForm,
                    new ArrayList<AssertionConsumerService>(), null);

            EntityDescriptor ent = generateSPEntityDescriptor("https://sp.bfh.ch", sp, null, new ArrayList<ContactPerson>());

            SignatureUtil.SignSignableSAMLObject(ent, credential);

            SamlUtil.writeXMLObjectToXML("src/main/resources/metadata/sp-metadata.xml", ent);

        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException | UnrecoverableEntryException ex) {
            Logger.getLogger(MetadataUtil.class.getName()).log(Level.SEVERE, null, ex);
        } catch (Exception ex) {
            Logger.getLogger(MetadataUtil.class.getName()).log(Level.SEVERE, null, ex);
        }

        try {
            EntityDescriptor ent1 = (EntityDescriptor) SamlUtil.createXMLObjectFromXMLSource("src/main/resources/metadata/sp-metadata.xml");

            if (SignatureUtil.istSignatureValid(ent1)) {
                System.out.println("The signature is valid");
            } else {
                System.out.println("The signature is not valid");
            }
        } catch (Exception ex) {
            System.err.println("Could not create EntityDescriptor");
        }

        Assertion assertion = (Assertion) SamlUtil.createXMLObject(Assertion.DEFAULT_ELEMENT_NAME);
        try {
            Element plaintextElement = SamlUtil.marshall(assertion);
            String originalAssertionString = XMLHelper.nodeToString(plaintextElement);
            System.out.println("Assertion String: " + originalAssertionString);
            
            KeyStore.PrivateKeyEntry entry = CertificateUtil.getKeyStore("/Users/Yandy/Desktop/myidp.jks", "moleson", "tomcat", "moleson");

            EncryptedAssertion encAss = EncrypterUtil.encryptAssertion(assertion, (X509Certificate)entry.getCertificate());
            Element plaintextEncr = SamlUtil.marshall(encAss);
            System.out.println("Encrypted Assertion: "+XMLHelper.nodeToString(plaintextEncr));
            
            BasicX509Credential credential = new BasicX509Credential();
            credential.setPrivateKey(entry.getPrivateKey());
            credential.setPublicKey(entry.getCertificate().getPublicKey());
          
            List<Credential> credentials = new ArrayList<>();
            credentials.add(credential);
            
            Assertion decrytedAssert = EncrypterUtil.decryptEncryptedAssertion(encAss, credentials);
            String decryptAssertionString = XMLHelper.nodeToString(plaintextElement);
            System.out.println("Decrypted Assertion String: " + decryptAssertionString);
        
        } catch (MarshallingException | KeyException | DecryptionException ex) {
            Logger.getLogger(MetadataUtil.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        
    }

}
