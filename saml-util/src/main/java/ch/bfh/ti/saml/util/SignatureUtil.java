package ch.bfh.ti.saml.util;
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
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.validation.ValidationException;

/**
 *
 * @author yandy
 */
public class SignatureUtil {

    /**
     *
     * @param sigSamlObj
     * @param credential
     */
    public static void SignSignableSAMLObject(SignableSAMLObject sigSamlObj, BasicX509Credential credential) {

        Credential signingCredential = credential;
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
        //TODO test trust
        SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
        Signature sig = xmlObject.getSignature();
        if (sig == null) {
            //TODO "No signature on XML object");
            return false;
        }
        try {
            profileValidator.validate(sig);
        } catch (ValidationException ex) {
            //TODO "Indicates signature did not conform to SAML Signature profile");
            return false;
        }

        X509Certificate certToCheck;
        try {
            final List<X509Certificate> certificates = KeyInfoHelper
                    .getCertificates(sig.getKeyInfo());
            if (certificates.isEmpty()) {
                //TODO "No certificates in KeyInfo found");
                return false;
            }
            certToCheck = certificates.get(0);
            
        } catch (CertificateException ex) {
            //TODO "No valid keyinfo in signature found");
            return false;
        }

        BasicX509Credential credential = new BasicX509Credential();      
        
        try {
            credential.setEntityCertificate(certToCheck);
            SignatureValidator sigValidator = new SignatureValidator(credential);
            sigValidator.validate(sig);
        } catch (ValidationException e) {
           //TODO "Indicates signature was not cryptographically valid, or possibly a processing error");
            //"Signature was not valid";
            return false;
        }
        return true;
    }
}
