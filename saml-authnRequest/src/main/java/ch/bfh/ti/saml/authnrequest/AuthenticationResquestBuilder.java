package ch.bfh.ti.saml.authnrequest;

import ch.bfh.ti.saml.util.SamlUtil;
import java.util.UUID;
import org.joda.time.DateTime;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameIDPolicy;

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
    public AuthnRequest buildAuthnRequest(Issuer issuer, NameIDPolicy nameIdPolicy){

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
        return authnRequest;

    }

}
