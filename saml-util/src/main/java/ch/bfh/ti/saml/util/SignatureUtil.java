package ch.bfh.ti.saml.util;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityConfiguration;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.keyinfo.KeyInfoHelper;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.validation.ValidationException;

/**
 *
 * @author admin
 */
public class SignatureUtil {

    /**
     *
     * @param sigSamlObj
     * @param keyEntry
     */
    public static void SignSignableSAMLObject(SignableSAMLObject sigSamlObj, KeyStore.PrivateKeyEntry keyEntry) {

        Credential signingCredential = getSigningCredential(keyEntry);
        Signature signature = (Signature) SamlUtil.createXMLObject(Signature.DEFAULT_ELEMENT_NAME);
        signature.setSigningCredential(signingCredential);
//        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
//        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

        SecurityConfiguration secConfig = Configuration.getGlobalSecurityConfiguration();

        try {
            SecurityHelper.prepareSignatureParams(signature, signingCredential, secConfig, null);
        } catch (SecurityException ex) {
            ex.printStackTrace();
            //TODO
        }
        sigSamlObj.setSignature(signature);

        try {
            SamlUtil.marshall(sigSamlObj);
        } catch (MarshallingException e) {
            e.printStackTrace();
            //TODO
        }
        try {
            Signer.signObject(signature);
        } catch (SignatureException e) {
            //TODO
            e.printStackTrace();
        }
    }

    /**
     *
     * @param xmlObject
     * @return
     */
    public static boolean istSignatureValid(final SignableSAMLObject xmlObject) {

        SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
        Signature sig = xmlObject.getSignature();
        if (sig == null) {
            System.err.println("No signature on XML object");
            return false;
        }
        try {
            profileValidator.validate(sig);
        } catch (ValidationException ex) {
            System.err.println("Indicates signature did not conform to SAML Signature profile");
            return false;
        }

        X509Certificate certToCheck;
        try {
            final List<X509Certificate> certificates = KeyInfoHelper
                    .getCertificates(sig.getKeyInfo());
            if (certificates.isEmpty()) {
                System.err.println("No certificates in KeyInfo found");
                return false;
            }
            certToCheck = certificates.get(0);
            
        } catch (CertificateException ex) {
            System.err.println("No valid keyinfo in signature found");
            return false;
        }

        BasicX509Credential credential = new BasicX509Credential();      
        
        try {
            credential.setEntityCertificate(certToCheck);
            SignatureValidator sigValidator = new SignatureValidator(credential);
            sigValidator.validate(sig);
        } catch (ValidationException e) {
            System.err.println("Indicates signature was not cryptographically valid, or possibly a processing error");
            //"Signature was not valid";
            return false;
        }
        return true;
    }

    /**
     *
     * @param keyStorePath
     * @param keyStorePassw
     * @param alias
     * @param aliasPassword
     * @return
     * @throws KeyStoreException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws UnrecoverableEntryException
     */
    public static KeyStore.PrivateKeyEntry getKeyStore(String keyStorePath, String keyStorePassw, String alias, String aliasPassword) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, UnrecoverableEntryException {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(new FileInputStream(keyStorePath), keyStorePassw.toCharArray());
        KeyStore.PrivateKeyEntry keyEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(alias, new KeyStore.PasswordProtection(aliasPassword.toCharArray()));
        return keyEntry;
    }

    /**
     *
     * @param keyEntry
     * @return
     */
    private static BasicX509Credential getSigningCredential(KeyStore.PrivateKeyEntry keyEntry) {
        BasicX509Credential credential = new BasicX509Credential();
        credential.setPrivateKey(keyEntry.getPrivateKey());
        credential.setEntityCertificate((X509Certificate) keyEntry.getCertificate());
        return credential;
    }
}
