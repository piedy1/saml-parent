package ch.bfh.ti.saml.util;

import java.security.KeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import org.opensaml.common.SAMLObject;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.core.EncryptedAttribute;
import org.opensaml.saml2.core.EncryptedID;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.encryption.Decrypter;
import org.opensaml.saml2.encryption.EncryptedElementTypeEncryptedKeyResolver;
import org.opensaml.saml2.encryption.Encrypter;
import org.opensaml.saml2.encryption.Encrypter.KeyPlacement;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.encryption.ChainingEncryptedKeyResolver;
import org.opensaml.xml.encryption.DecryptionException;
import org.opensaml.xml.encryption.EncryptionConstants;
import org.opensaml.xml.encryption.EncryptionException;
import org.opensaml.xml.encryption.EncryptionParameters;
import org.opensaml.xml.encryption.InlineEncryptedKeyResolver;
import org.opensaml.xml.encryption.KeyEncryptionParameters;
import org.opensaml.xml.encryption.SimpleRetrievalMethodEncryptedKeyResolver;
import org.opensaml.xml.security.credential.CollectionCredentialResolver;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.security.keyinfo.KeyInfoGeneratorFactory;
import org.opensaml.xml.security.keyinfo.KeyInfoProvider;
import org.opensaml.xml.security.keyinfo.LocalKeyInfoCredentialResolver;
import org.opensaml.xml.security.keyinfo.provider.InlineX509DataProvider;
import org.opensaml.xml.security.keyinfo.provider.RSAKeyValueProvider;
import org.opensaml.xml.security.x509.BasicX509Credential;

/**
 *
 * @author yandy
 */
public class EncrypterUtil {

    /**
     * 
     * @param assertion
     * @param certificate
     * @return
     * @throws EncryptionException
     * @throws NoSuchAlgorithmException
     * @throws KeyException 
     */
    public static EncryptedAssertion encryptAssertion(Assertion assertion, X509Certificate certificate) throws EncryptionException, NoSuchAlgorithmException, KeyException {

        Encrypter encrypter = getEncrypter(certificate);
        EncryptedAssertion encrypted = encrypter.encrypt(assertion);
        return encrypted;
    }

    /**
     * 
     * @param attribute
     * @param certificate
     * @return
     * @throws EncryptionException
     * @throws NoSuchAlgorithmException
     * @throws KeyException 
     */
    public static EncryptedAttribute encryptAttribute(Attribute attribute, X509Certificate certificate) throws EncryptionException, NoSuchAlgorithmException, KeyException {
        // The Attribute to be encrypted
        Attribute attributeToEncrypt = attribute;
        Encrypter samlEncrypter = getEncrypter(certificate);
        return samlEncrypter.encrypt(attributeToEncrypt);
    }

    /**
     *
     * @param nameId
     * @param certificate
     * @return
     */
    public static EncryptedID encryptNameID(NameID nameId, X509Certificate certificate) throws EncryptionException, NoSuchAlgorithmException, KeyException {
        // The NameID to be encrypted
        NameID nameIdToEncrypt = nameId;
        Encrypter samlEncrypter = getEncrypter(certificate);
        return samlEncrypter.encrypt(nameIdToEncrypt);

    }
    
    /**
     * 
     * @param encryptAssert
     * @param credentials
     * @return
     * @throws DecryptionException 
     */
    public static Assertion decryptEncryptedAssertion(EncryptedAssertion encryptAssert, List<Credential> credentials) throws DecryptionException {
        
        EncryptedAssertion encryptedAssertion = encryptAssert;
        Decrypter samlDecrypter = getDecrypter(credentials);
        
        return samlDecrypter.decrypt(encryptedAssertion);
    }
    
    /**
     * 
     * @param encryptAttr
     * @param credentials
     * @return
     * @throws DecryptionException 
     */
    public static Attribute decryptEncryptedAttribute(EncryptedAttribute encryptAttr, List<Credential> credentials) throws DecryptionException {
        
        EncryptedAttribute encryptedAttr = encryptAttr;
        Decrypter samlDecrypter = getDecrypter(credentials);
        
        return samlDecrypter.decrypt(encryptedAttr);
    }
    
    /**
     * 
     * @param encryptID
     * @param credentials
     * @return
     * @throws DecryptionException 
     */
    public static SAMLObject decryptEncryptedNameID(EncryptedID encryptID, List<Credential> credentials) throws DecryptionException {
        
        EncryptedID encryptedId = encryptID;
        Decrypter samlDecrypter = getDecrypter(credentials);
        
        return samlDecrypter.decrypt(encryptedId);
    }
    

    
    private static Encrypter getEncrypter(X509Certificate certificate) throws NoSuchAlgorithmException, KeyException {

        BasicX509Credential credential = new BasicX509Credential();
        credential.setEntityCertificate(certificate);

        EncryptionParameters encParams = new EncryptionParameters();
        encParams.setAlgorithm(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128);

        KeyEncryptionParameters kekParams = new KeyEncryptionParameters();
        kekParams.setEncryptionCredential(credential);
        kekParams.setAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP);
        KeyInfoGeneratorFactory kigf = Configuration.getGlobalSecurityConfiguration()
                .getKeyInfoGeneratorManager().getDefaultManager().getFactory(credential);
        kekParams.setKeyInfoGenerator(kigf.newInstance());

        Encrypter samlEncrypter = new Encrypter(encParams, kekParams);
        samlEncrypter.setKeyPlacement(KeyPlacement.PEER);

        return samlEncrypter;
    }
    
    /**
     * 
     * @param credentials
     * @return 
     */
    private static Decrypter getDecrypter(List<Credential> credentials){
     // Collection of local credentials, where each contains
        // a private key that corresponds to a public key that may
        // have been used by other parties for encryption
        List<Credential> localCredentials = credentials;

        CollectionCredentialResolver localCredResolver = new CollectionCredentialResolver(localCredentials);

        // Support EncryptedKey/KeyInfo containing decryption key hints via
        // KeyValue/RSAKeyValue and X509Data/X509Certificate
        List<KeyInfoProvider> kiProviders = new ArrayList<>();
        kiProviders.add(new RSAKeyValueProvider());
        kiProviders.add(new InlineX509DataProvider());

        // Resolves local credentials by using information in the EncryptedKey/KeyInfo to query the supplied
        // local credential resolver.
        KeyInfoCredentialResolver kekResolver = new LocalKeyInfoCredentialResolver(kiProviders, localCredResolver);

        // Supports resolution of EncryptedKeys by 3 common placement mechanisms
        ChainingEncryptedKeyResolver encryptedKeyResolver = new ChainingEncryptedKeyResolver();
        encryptedKeyResolver.getResolverChain().add(new InlineEncryptedKeyResolver());
        encryptedKeyResolver.getResolverChain().add(new EncryptedElementTypeEncryptedKeyResolver());
        encryptedKeyResolver.getResolverChain().add(new SimpleRetrievalMethodEncryptedKeyResolver());

        return new Decrypter(null, kekResolver, encryptedKeyResolver);    
        
    }
}
