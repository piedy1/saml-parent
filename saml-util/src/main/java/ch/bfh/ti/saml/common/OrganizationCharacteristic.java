package ch.bfh.ti.saml.common;

import org.opensaml.saml2.metadata.OrganizationDisplayName;
import org.opensaml.saml2.metadata.OrganizationName;
import org.opensaml.saml2.metadata.OrganizationURL;

/**
 *
 * @author Yandy
 */
public class OrganizationCharacteristic {

    private OrganizationDisplayName orgDisName;
    private OrganizationName orgName;
    private OrganizationURL orgUrl;

    public OrganizationCharacteristic(OrganizationDisplayName orgDisName, OrganizationName orgName, OrganizationURL orgUrl) {
        this.orgDisName = orgDisName;
        this.orgName = orgName;
        this.orgUrl = orgUrl;
    }
 
    public OrganizationDisplayName getOrgDisName() {
        return orgDisName;
    }

    public void setOrgDisName(OrganizationDisplayName orgDisName) {
        this.orgDisName = orgDisName;
    }

    public OrganizationName getOrgName() {
        return orgName;
    }

    public void setOrgName(OrganizationName orgName) {
        this.orgName = orgName;
    }

    public OrganizationURL getOrgUrl() {
        return orgUrl;
    }

    public void setOrgUrl(OrganizationURL orgUrl) {
        this.orgUrl = orgUrl;
    }

    
}
