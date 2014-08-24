package ch.bfh.ti.saml.authnrequest;

import ch.bfh.ti.saml.util.SamlUtil;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.UUID;
import org.joda.time.DateTime;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameIDPolicy;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityConfiguration;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;

/**
 *
 * @author admin
 */
public class AuthenticationResquestBuilder {

    // Specifies the human-readable name of the requester
    private final String providerName;

    // Specifies the location URL where the <Response> message MUST be retorned
    private final String assertionConsumerServiceUrl;

    // This is the appropriate URL of the IdP.
    private final String destination;

    // A URI reference that identifies a SAML protocol binding to be used when returning the <Response>
    private final String protocolBinding;

    /**
     *
     * @param providerNameValue
     * @param assertionConsumerServiceUrl
     * @param destination
     * @param protocolBinding
     */
    public AuthenticationResquestBuilder(String providerNameValue, String assertionConsumerServiceUrl,
            String destination, String protocolBinding) {

        this.providerName = providerNameValue;
        this.assertionConsumerServiceUrl = assertionConsumerServiceUrl;
        this.destination = destination;
        this.protocolBinding = protocolBinding;
    }

    /**
     *
     * @param issuer
     * @param nameIdPolicy
     * @return
     */
    public AuthnRequest buildAuthnRequest(Issuer issuer, NameIDPolicy nameIdPolicy) throws SecurityException {

        AuthnRequest authnRequest = (AuthnRequest) SamlUtil.createXMLObject(AuthnRequest.DEFAULT_ELEMENT_NAME);
        authnRequest.setAssertionConsumerServiceURL(assertionConsumerServiceUrl);
        authnRequest.setDestination(destination);
        authnRequest.setID("_" + UUID.randomUUID().toString());
        authnRequest.setIssueInstant(new DateTime());
        authnRequest.setProtocolBinding(protocolBinding);
        authnRequest.setProviderName(providerName);
        authnRequest.setIssuer(issuer);
        authnRequest.setNameIDPolicy(nameIdPolicy);
    //  authnRequest.setForceAuthn(true);
    //  authnRequest.setIsPassive(false);

        Credential signingCredential = getSigningCredential();
        Signature signature = (Signature) SamlUtil.createXMLObject(Signature.DEFAULT_ELEMENT_NAME);
        signature.setSigningCredential(signingCredential);
//      signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
//      signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

        SecurityConfiguration secConfig = Configuration.getGlobalSecurityConfiguration();

        SecurityHelper.prepareSignatureParams(signature, signingCredential, secConfig, null);
        authnRequest.setSignature(signature);

        try {
            SamlUtil.marshall(authnRequest);
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
        return authnRequest;

    }

    public BasicX509Credential getSigningCredential() {
        // Load the KeyStore and get the signing key and certificate.
        KeyStore ks;
        try {
            ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(new FileInputStream("/Users/Yandy/Desktop/ch-demo.jks"), "demo-ch".toCharArray());
            KeyStore.PrivateKeyEntry keyEntry = (KeyStore.PrivateKeyEntry) ks.getEntry("demo-ch", new KeyStore.PasswordProtection("demo-ch".toCharArray()));
            BasicX509Credential credential = new BasicX509Credential();
            credential.setPrivateKey(keyEntry.getPrivateKey());
            credential.setEntityCertificate((X509Certificate) keyEntry.getCertificate());

            return credential;
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException | IOException | CertificateException ex) {
            //TODO
            ex.printStackTrace();
        }

        return null;
    }

}
