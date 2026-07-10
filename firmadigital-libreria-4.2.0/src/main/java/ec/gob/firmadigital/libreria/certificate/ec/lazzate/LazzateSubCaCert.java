/*
 * Copyright (C) 2022
 * Authors: Henry Carrera
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.*
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package ec.gob.firmadigital.libreria.certificate.ec.lazzate;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Set;

/**
 * Certificado intermedio de Lazzate, representado como un objeto
 * <code>X509Certificate</code>.
 *
 * @author Henry Carrera <henry@hyrserv.com>
 */
public class LazzateSubCaCert extends X509Certificate {

    private X509Certificate certificate;

    public LazzateSubCaCert() {
        super();

        StringBuilder cer = new StringBuilder();
        cer.append("-----BEGIN CERTIFICATE-----\n");
        cer.append("MIIE/zCCA+egAwIBAgIUewru6cS/TNFZnzF1y+HlbyVQKkkwDQYJKoZIhvcNAQEL\n");
        cer.append("BQAwgbYxCzAJBgNVBAYTAkVDMRowGAYDVQQIExFRdWl0byAtIFBpY2hpbmNoYTEO\n");
        cer.append("MAwGA1UEBxMFUXVpdG8xJDAiBgkqhkiG9w0BCQEWFWNlcnRpZmljYWRvc0BlbmV4\n");
        cer.append("dC5lYzEbMBkGA1UEChMSTGF6emF0ZSBDaWEuIEx0ZGEuMR4wHAYDVQQLExVFbnRl\n");
        cer.append("IGRlIENlcnRpZmljYWNpb24xGDAWBgNVBAMTD0xhenphdGUgUm9vdCBDQTAeFw0y\n");
        cer.append("MjEwMTMxNjU3MDlaFw0zNzEwMTMxNjU3MDlaMIHIMQswCQYDVQQGEwJFQzEaMBgG\n");
        cer.append("A1UECBMRUXVpdG8gLSBQaWNoaW5jaGExDjAMBgNVBAcTBVF1aXRvMSQwIgYJKoZI\n");
        cer.append("hvcNAQkBFhVjZXJ0aWZpY2Fkb3NAZW5leHQuZWMxDjAMBgNVBGETBTU5MzgyMRsw\n");
        cer.append("GQYDVQQKExJMYXp6YXRlIENpYS4gTHRkYS4xHjAcBgNVBAsTFUVudGUgZGUgQ2Vy\n");
        cer.append("dGlmaWNhY2lvbjEaMBgGA1UEAxMRTGF6emF0ZSBFbWlzb3IgQ0EwggEiMA0GCSqG\n");
        cer.append("SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCwFNnWJH6zpz6C3tPGLmwrwIpp1mDVzmzw\n");
        cer.append("x3mIXXm7wMcwT9U4ErQu3OnfMsWYRo73zNZ2gtPMUrvoQuvm6gFvjTnSmlZf3gXH\n");
        cer.append("V9XzF/M1hFF/Emwz9IJoQ2qsFPUQ6AuOQ8sXoyorLRfLWcY9nXpW5qAUAmh4+QTL\n");
        cer.append("JasbmrrhFSZ+gwmyJXFUOKwhuhZ4kpwJXQvSlnNRUtr01oAzJXQAfQZuaWxCugjC\n");
        cer.append("oORVy4xuiG9iSAFL2WappFGam0xX68C8WaFMITlUTIzDk1gtyHa7YfZhTWf9fK1w\n");
        cer.append("TZYUuzLF92jzPQXhOWTpPOiWwFuGl4s2lJ+nFhfURj4d4gnB8VMxAgMBAAGjgfAw\n");
        cer.append("ge0wDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwHwYDVR0jBBgw\n");
        cer.append("FoAU4Jb2x9aG40aQMEeeXa2fTc9E1bAwgYYGA1UdIAR/MH0wewYJKwYBBAGDz3YB\n");
        cer.append("MG4wbAYIKwYBBQUHAgIwYAxeRWwgcHJlc2VudGUgY2VydGlmaWNhZG8gZXMgZW1p\n");
        cer.append("dGlkbyBlbiBiYXNlIGEgbGFzIHBvbMOtdGljYXMgZGUgc2VndXJpZGFkIGRlIExh\n");
        cer.append("enphdGUgQ2lhLiBMdGRhLjAdBgNVHQ4EFgQU4umBjHsfY1yzy+fymq8QhkS7CgUw\n");
        cer.append("DQYJKoZIhvcNAQELBQADggEBAD+tGgVNim3d2iO2jYiN1A500pSmQN6gIqr2LDih\n");
        cer.append("T3AD29OkoCG4wVisq7pNzfjVaK0ZF2RyW/SGX94ASp0/qYdNsxHQvW2uz/rVRsnJ\n");
        cer.append("A9UavHcg+5qu86Kvv5UZi2rmaFqs9fFVO/sAgpZ8qYSY6D6aZqXrxd6iP3U02aOq\n");
        cer.append("bpjDlxl9sYrU7xJzdZ7qOH1ChyJkd/y8UtlD/D9G+urIrgDH4du1Bl255RfYBgdS\n");
        cer.append("e5fDZBA5MEdD3IDZZ1hnU0cwM7tWRl1DoUuFYXaTNapMstFURHXMsf4avN1leoYp\n");
        cer.append("3ms97TNEm9moPG4QNAzmGy8YaWsq/JItoUbgHDa7uWTxgpc=\n");
        cer.append("-----END CERTIFICATE-----\n");

        try {
            InputStream is = new ByteArrayInputStream(cer.toString().getBytes("UTF-8"));
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            this.certificate = (X509Certificate) cf.generateCertificate(is);
        } catch (UnsupportedEncodingException | GeneralSecurityException e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Override
    public void checkValidity() throws CertificateExpiredException, CertificateNotYetValidException {
        certificate.checkValidity();
    }

    @Override
    public void checkValidity(Date date) throws CertificateExpiredException, CertificateNotYetValidException {
        certificate.checkValidity(date);
    }

    @Override
    public int getBasicConstraints() {
        return certificate.getBasicConstraints();
    }

    @Override
    public Principal getIssuerDN() {
        return certificate.getIssuerDN();
    }

    @Override
    public boolean[] getIssuerUniqueID() {
        return certificate.getIssuerUniqueID();
    }

    @Override
    public boolean[] getKeyUsage() {
        return certificate.getKeyUsage();
    }

    @Override
    public Date getNotAfter() {
        return certificate.getNotAfter();
    }

    @Override
    public Date getNotBefore() {
        return certificate.getNotBefore();
    }

    @Override
    public BigInteger getSerialNumber() {
        return certificate.getSerialNumber();
    }

    @Override
    public String getSigAlgName() {
        return certificate.getSigAlgName();
    }

    @Override
    public String getSigAlgOID() {
        return certificate.getSigAlgOID();
    }

    @Override
    public byte[] getSigAlgParams() {
        return certificate.getSigAlgParams();
    }

    @Override
    public byte[] getSignature() {
        return certificate.getSignature();
    }

    @Override
    public Principal getSubjectDN() {
        return certificate.getSubjectDN();
    }

    @Override
    public boolean[] getSubjectUniqueID() {
        return certificate.getSubjectUniqueID();
    }

    @Override
    public byte[] getTBSCertificate() throws CertificateEncodingException {
        return certificate.getTBSCertificate();
    }

    @Override
    public int getVersion() {
        return certificate.getVersion();
    }

    @Override
    public byte[] getEncoded() throws CertificateEncodingException {
        return certificate.getEncoded();
    }

    @Override
    public PublicKey getPublicKey() {
        return certificate.getPublicKey();
    }

    @Override
    public String toString() {
        return certificate.toString();
    }

    @Override
    public void verify(PublicKey key) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException,
            NoSuchProviderException, SignatureException {
        certificate.verify(key);
    }

    @Override
    public void verify(PublicKey key, String sigProvider) throws CertificateException, NoSuchAlgorithmException,
            InvalidKeyException, NoSuchProviderException, SignatureException {
        certificate.verify(key, sigProvider);
    }

    @Override
    public Set<String> getCriticalExtensionOIDs() {
        return certificate.getCriticalExtensionOIDs();
    }

    @Override
    public byte[] getExtensionValue(String oid) {
        return certificate.getExtensionValue(oid);
    }

    @Override
    public Set<String> getNonCriticalExtensionOIDs() {
        return certificate.getNonCriticalExtensionOIDs();
    }

    @Override
    public boolean hasUnsupportedCriticalExtension() {
        return certificate.hasUnsupportedCriticalExtension();
    }
}
