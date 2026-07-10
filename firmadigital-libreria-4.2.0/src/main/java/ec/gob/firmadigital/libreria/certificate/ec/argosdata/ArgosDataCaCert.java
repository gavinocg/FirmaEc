/*
 * Copyright (C) 2022
 * Authors: Ricardo Arguello
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
package ec.gob.firmadigital.libreria.certificate.ec.argosdata;

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
 * Certificado raiz de Argos Data, representado como un objeto
 * <code>X509Certificate</code>.
 *
 * @author Ricardo Arguello
 */
public class ArgosDataCaCert extends X509Certificate {

    private X509Certificate certificate;

    public ArgosDataCaCert() {
        super();

        StringBuilder cer = new StringBuilder();
        cer.append("-----BEGIN CERTIFICATE-----\n");
        cer.append("MIIDhTCCAm2gAwIBAgIRALExbzvYmB+gvQ7j1vn+z9EwDQYJKoZIhvcNAQELBQAw\n");
        cer.append("XDELMAkGA1UEBhMCRUMxEjAQBgNVBAoMCUFyZ29zRGF0YTEVMBMGA1UECwwMQXJn\n");
        cer.append("b3NEYXRhIENBMSIwIAYDVQQDDBlBcmdvc0RhdGEgUm9vdCBDQSAtU0hBMjU2MB4X\n");
        cer.append("DTIyMDYwOTE4MDkxMFoXDTMyMDYwOTE5MDkxMFowXDELMAkGA1UEBhMCRUMxEjAQ\n");
        cer.append("BgNVBAoMCUFyZ29zRGF0YTEVMBMGA1UECwwMQXJnb3NEYXRhIENBMSIwIAYDVQQD\n");
        cer.append("DBlBcmdvc0RhdGEgUm9vdCBDQSAtU0hBMjU2MIIBIjANBgkqhkiG9w0BAQEFAAOC\n");
        cer.append("AQ8AMIIBCgKCAQEAiL+DIRt8+qCAh9VNlq6chZRYNCernnENvGvoilsNIei1UYht\n");
        cer.append("BL0wWj2rNtRaY5LGtn6ivMsv7DokN8EOpj+y+x/KUmuCQJJt99ylvei2u/iuUTPZ\n");
        cer.append("nxmB7iOww53kLF/Wy5VeFBFEG7prRyLecsvi7BKw2LPpLa+dqauhfMKwQKXz+5Py\n");
        cer.append("InjpMKjb3vg/W7ho9w+VZ3RUm1boP6RxvnWZKgOkdDrkZpD3jPXkn1WNqs70freu\n");
        cer.append("4tEJ7YlQje6fSvvzv9Ra4P+D1oDOOIg/qC20PLFlgdmQKT4SAw5AV/Nso/TLRI81\n");
        cer.append("S4lCmsj55lKWfvV2p14TkypPOWrHO2Y2VaYxtwIDAQABo0IwQDAPBgNVHRMBAf8E\n");
        cer.append("BTADAQH/MB0GA1UdDgQWBBR5P8fvvzpxJ/XaJ70JDuj/xJgOTDAOBgNVHQ8BAf8E\n");
        cer.append("BAMCAYYwDQYJKoZIhvcNAQELBQADggEBAEJNF6X5KJ91dXewbnRFYlTHn49SC5FE\n");
        cer.append("4oEKpQPBL37iGeBIGdZeCvIErsxnVrDolu0/k1tRYHKPWlgR/i0d7pVMX0n6dZGr\n");
        cer.append("vdZX7XXMLIOHNrQaeIIcQf9TB8p2iIAUzQ11iyt7y34U0XtWSUKWkjgtey5rfJea\n");
        cer.append("U9UdGXMI9WjWOFtC4EcJI50QA8X5ImzmK34pl/3xk6MqJvdNM8Hg7hZpjyobig/8\n");
        cer.append("XrfBOZYhRptIJ9DaTA52cbVEWhpB+ZFzyb6AzXbYf8zkquzJwULMIvBPRcJP6wWi\n");
        cer.append("9CGTnOYtIAoXOQuSdr61PIuIJPBBDuyX2XW3rJ7476mevsR0oQH/sOY=\n");
        cer.append("-----END CERTIFICATE-----");

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
