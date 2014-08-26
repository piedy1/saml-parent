package ch.bfh.ti.saml.util;

import java.security.KeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.core.EncryptedAttribute;
import org.opensaml.saml2.core.EncryptedID;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.encryption.Decrypter;
import org.opensaml.saml2.encryption.Encrypter;
import org.opensaml.saml2.encryption.Encrypter.KeyPlacement;
import org.opensaml.xml.encryption.DecryptionException;
import org.opensaml.xml.encryption.EncryptionConstants;
import org.opensaml.xml.encryption.EncryptionException;
import org.opensaml.xml.encryption.EncryptionParameters;
import org.opensaml.xml.encryption.InlineEncryptedKeyResolver;
import org.opensaml.xml.encryption.KeyEncryptionParameters;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.keyinfo.StaticKeyInfoCredentialResolver;
import org.opensaml.xml.security.x509.BasicX509Credential;

/**
 *
 * @author yandy
 */
public class EncrypterUtil {

    public static EncryptedAssertion encryptAssertion(Assertion assertion, X509Certificate certificate) throws EncryptionException, NoSuchAlgorithmException, KeyException {

        Encrypter encrypter = getEncrypter(certificate);
        EncryptedAssertion encrypted = encrypter.encrypt(assertion);
        return encrypted;
    }

    public static Assertion decryptEncryptedAssertion(EncryptedAssertion encryptAssert, Credential credential) throws DecryptionException {
        EncryptedAssertion encryptedAssertion = encryptAssert;

        // This credential - obtained by some unspecified mechanism -
        // contains the recipient's PrivateKey to be used for key decryption
        Credential decryptionCredential = credential;

        StaticKeyInfoCredentialResolver skicr = new StaticKeyInfoCredentialResolver(decryptionCredential);

        // The EncryptedKey is assumed to be contained within the
        // EncryptedAssertion/EncryptedData/KeyInfo.      
        Decrypter samlDecrypter = new Decrypter(null, skicr, new InlineEncryptedKeyResolver());

        return samlDecrypter.decrypt(encryptedAssertion);
    }

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

    private static Encrypter getEncrypter(X509Certificate certificate) throws NoSuchAlgorithmException, KeyException {

        Credential symmetricCredential = SecurityHelper.getSimpleCredential(
        SecurityHelper.generateSymmetricKey(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128));
        BasicX509Credential credential = new BasicX509Credential();
        credential.setEntityCertificate(certificate);
        EncryptionParameters encParams = new EncryptionParameters();
        encParams.setAlgorithm(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128);
        encParams.setEncryptionCredential(symmetricCredential);

        KeyEncryptionParameters kek = new KeyEncryptionParameters();
        kek.setAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSA15);
        kek.setEncryptionCredential(credential);

        Encrypter encrypter = new Encrypter(encParams, kek);
        encrypter.setKeyPlacement(KeyPlacement.INLINE);

        return encrypter;
    }
}
