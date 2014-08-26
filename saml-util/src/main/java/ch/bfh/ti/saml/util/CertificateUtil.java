/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ch.bfh.ti.saml.util;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.keyinfo.KeyInfoGenerator;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.security.x509.X509KeyInfoGeneratorFactory;
import org.opensaml.xml.signature.KeyInfo;

/**
 *
 * @author admin
 */
public class CertificateUtil {
    
    /**
     * 
     * @param credential
     * @return
     * @throws SecurityException 
     */
    public static KeyInfo getKeyInfo(X509Credential credential) throws SecurityException {
        X509KeyInfoGeneratorFactory keyInfoGeneratorFactory = new X509KeyInfoGeneratorFactory();
        keyInfoGeneratorFactory.setEmitEntityCertificate(true);
        KeyInfoGenerator keyInfoGenerator = keyInfoGeneratorFactory.newInstance();
        return keyInfoGenerator.generate(credential);
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
    public static BasicX509Credential getSigningCredential(KeyStore.PrivateKeyEntry keyEntry){
        BasicX509Credential credential = new BasicX509Credential();
        credential.setPrivateKey(keyEntry.getPrivateKey());
        credential.setEntityCertificate((X509Certificate) keyEntry.getCertificate());
        return credential;
    }

}
