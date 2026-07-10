/*
 * Copyright (C) 2024
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
public class LazzateSubCa2Cert extends X509Certificate {

    private X509Certificate certificate;

    public LazzateSubCa2Cert() {
        super();

        StringBuilder cer = new StringBuilder();
        cer.append("-----BEGIN CERTIFICATE-----\n");
        cer.append("MIIEPjCCAyagAwIBAgIUV4erTYAKKzD+cP6G4Ux/FVgRutEwDQYJKoZIhvcNAQEL\n");
        cer.append("BQAwgYkxCzAJBgNVBAYTAkVDMRIwEAYDVQQIDAlQSUNISU5DSEExDjAMBgNVBAcM\n");
        cer.append("BVFVSVRPMRswGQYDVQQKDBJMYXp6YXRlIENpYS4gTHRkYS4xHjAcBgNVBAsMFUVu\n");
        cer.append("dGUgZGUgQ2VydGlmaWNhY2lvbjEZMBcGA1UEAwwQTGF6emF0ZSBSb290IENBMjAg\n");
        cer.append("Fw0yMzExMjkyMjEzMzVaGA8yMDUzMTEyMTIyMTMzNVowRzELMAkGA1UEBhMCRUMx\n");
        cer.append("GzAZBgNVBAoMEkxhenphdGUgQ2lhLiBMdGRhLjEbMBkGA1UEAwwSTGF6emF0ZSBF\n");
        cer.append("bWlzb3IgQ0EyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4aEiyb01\n");
        cer.append("IImhFv2k1o+QVL1Uhi12XQh6E7roZiIpcKlQkDG6UW6aUjwXXNHsADKe/5UZhEP6\n");
        cer.append("LFJAiTGPYEB818Ce5ONAs9P20EcNgox44rSQDpFVQffH7Hbp5Rq1QkCmU5I6NCW1\n");
        cer.append("ddraw6kxESjvtoIrHy/eGrtt9ptTOS7IHA5pZS+wu1liD6K/HTrIdKHTsQSMiYPy\n");
        cer.append("cVqZ2mUWtjRR7qxLCFV4thRYSOr+qVVmrhICR8pO4u5MGRLLidUR8gPZXmWCYKXu\n");
        cer.append("Fv0RTuztYnihYt9KgP4cnQBj56hb+i3BOU1QuSYNdO+WMpG0Ujthqd1dYZMkxHjK\n");
        cer.append("EkiQryxlbFAZjwIDAQABo4HcMIHZMB0GA1UdDgQWBBTtdkiwCvHJhoYMTEZk0gb4\n");
        cer.append("zNW9PjAfBgNVHSMEGDAWgBQSyTRfn3cPf1bel04Kk50Tp3BtxzASBgNVHRMBAf8E\n");
        cer.append("CDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjA1BgNVHR8ELjAsMCqgKKAmhiRodHRw\n");
        cer.append("Oi8vZW5leHQyLnh5ei9jcmwvbGF6emF0ZUNBMi5jcmwwPAYIKwYBBQUHAQEEMDAu\n");
        cer.append("MCwGCCsGAQUFBzABhiBodHRwOi8vZW5leHQyLnh5ejo4Nzc3L2Fkc3Mvb2NzcDAN\n");
        cer.append("BgkqhkiG9w0BAQsFAAOCAQEAQ5WeUskOVYag1yIbsUg32XSUDahdY00LtOK0O3Y5\n");
        cer.append("sEZwW12OKyKc2h9LU7UK7NZKbfLXX2le8/IIPbiRkfQ6yvjUOx+keK9IWQ4mzjXb\n");
        cer.append("w7eW1JR1eBlwAZNhtZZRQfPhSEu8MQIFVSYZyaTSaq5yf3JocQjh//KS/QBM7OFy\n");
        cer.append("niwyPxW4Yl9UVJeCyneAAVkQvC1icM7BUowcEdyuQ2m4zs+myJN7eqWhKMJ2vSDF\n");
        cer.append("G3HeanHHZGN1nKFt0+dLT6oV2ul1BuXT9Vtcb4de742PKkeMFFBr3f9E6K6vKffG\n");
        cer.append("QtL+jnfzs/tMf9Ze9U6rHv6Cy13CZXwadteise3LV31P6g==\n");
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
