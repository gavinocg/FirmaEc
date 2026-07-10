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
 * Certificado raiz de Lazzate, representado como un objeto
 * <code>X509Certificate</code>.
 *
 * @author Henry Carrera <henry@hyrserv.com>
 */
public class LazzateCaCert extends X509Certificate {

    private X509Certificate certificate;

    public LazzateCaCert() {
        super();

        StringBuilder cer = new StringBuilder();
        cer.append("-----BEGIN CERTIFICATE-----\n");
        cer.append("MIIEyzCCA7OgAwIBAgIUTWuFyYRCM4bAog3Hy1L3GOcMGcswDQYJKoZIhvcNAQEL\n");
        cer.append("BQAwgbYxCzAJBgNVBAYTAkVDMRowGAYDVQQIExFRdWl0byAtIFBpY2hpbmNoYTEO\n");
        cer.append("MAwGA1UEBxMFUXVpdG8xJDAiBgkqhkiG9w0BCQEWFWNlcnRpZmljYWRvc0BlbmV4\n");
        cer.append("dC5lYzEbMBkGA1UEChMSTGF6emF0ZSBDaWEuIEx0ZGEuMR4wHAYDVQQLExVFbnRl\n");
        cer.append("IGRlIENlcnRpZmljYWNpb24xGDAWBgNVBAMTD0xhenphdGUgUm9vdCBDQTAgFw0y\n");
        cer.append("MjEwMTMxNjAzNTFaGA8yMDUyMTAxMzE2MDM1MVowgbYxCzAJBgNVBAYTAkVDMRow\n");
        cer.append("GAYDVQQIExFRdWl0byAtIFBpY2hpbmNoYTEOMAwGA1UEBxMFUXVpdG8xJDAiBgkq\n");
        cer.append("hkiG9w0BCQEWFWNlcnRpZmljYWRvc0BlbmV4dC5lYzEbMBkGA1UEChMSTGF6emF0\n");
        cer.append("ZSBDaWEuIEx0ZGEuMR4wHAYDVQQLExVFbnRlIGRlIENlcnRpZmljYWNpb24xGDAW\n");
        cer.append("BgNVBAMTD0xhenphdGUgUm9vdCBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC\n");
        cer.append("AQoCggEBAMW9RmxCvmsrgpc5UGnISJKR4j9h3nuxx/BYt60Ew9oEmE6Wi13xzyhB\n");
        cer.append("aJ3CHTZKSkMd+pDb2BlIW5Y2bAeRjcEEFJIDLfqHsm/nOG3BOt31FKqYiaicYMfM\n");
        cer.append("gKJfnSh4KtyeVcrsPWeK6npruLyQvnNj14CTkgFSwZXOFejI8rwcH5f1/AuvjAzw\n");
        cer.append("K+EWcsFxfVwW+RxPI4enmriFZktSvXoAPmT918jU2jvydUCZi71poQw2On6WXOVa\n");
        cer.append("GxKHk9YX5OWy6abLWNgbDhdWVf7hMsQTuO+lml2+qEll7rwYDt+o/CLzLbX3FeRt\n");
        cer.append("fPzPVRz/TvzDKN+69Ntk9ToV28LBwjcCAwEAAaOBzDCByTAOBgNVHQ8BAf8EBAMC\n");
        cer.append("AQYwDwYDVR0TAQH/BAUwAwEB/zCBhgYDVR0gBH8wfTB7BgkrBgEEAYPPdgEwbjBs\n");
        cer.append("BggrBgEFBQcCAjBgDF5FbCBwcmVzZW50ZSBjZXJ0aWZpY2FkbyBlcyBlbWl0aWRv\n");
        cer.append("IGVuIGJhc2UgYSBsYXMgcG9sw610aWNhcyBkZSBzZWd1cmlkYWQgZGUgTGF6emF0\n");
        cer.append("ZSBDaWEuIEx0ZGEuMB0GA1UdDgQWBBTglvbH1objRpAwR55drZ9Nz0TVsDANBgkq\n");
        cer.append("hkiG9w0BAQsFAAOCAQEAVneZ4igXcgT8zVhiVLMmkfgdggC7W+Y5/+p1WNb5cvtY\n");
        cer.append("XuTzp0A5KTxVIaSvzdWeFhX59EkTJByC1UkopTU0JmbdlWCFoS6QLccX9gjYRqqp\n");
        cer.append("WQ0tm983a6+bl4mjR34jOHS+nFawDGSAPXzbGTk93OuiMMH/nsPX9wC7lltZK7+/\n");
        cer.append("O4VXwOcB/3KgaC4kzI+VVGz9ejB424G7zLy6W+fvn4RqWADW+QCC5Hmd6Apy9IyD\n");
        cer.append("owE05uoE5MCA0yAsEN5eZEq3XbvsdzfKOuJp9Uxh9MgnuKvU7ptG/Wvh27b0MmKA\n");
        cer.append("n/RnpZEaz2BYnOrDkyEubpwTHkYFIq9oojwwrcLd1A==\n");
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
