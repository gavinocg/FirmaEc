/*
 * Copyright (C) 2025
 * Authors: Misael Fernández, PrimeCoreLat
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
package ec.gob.firmadigital.libreria.certificate.ec.primecorelat;

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
 * Certificado subordinado de PRIMECORELAT (SubCA), representado como un objeto
 * <code>X509Certificate</code>.
 *
 * @author Henry Carrera <henry@hyrserv.com>
 */
public class PrimeCoreLatSubCa2Cert extends X509Certificate {

    private X509Certificate certificate;

    public PrimeCoreLatSubCa2Cert() {
        super();

        StringBuilder cer = new StringBuilder();
        cer.append("-----BEGIN CERTIFICATE-----\n");
        cer.append("MIIHgDCCBWigAwIBAgIULAMemOdF7bmqluoR76aOjuPZazowDQYJKoZIhvcNAQEL\n");
        cer.append("BQAwgbIxCzAJBgNVBAYTAkVDMRIwEAYDVQQIDAlQSUNISU5DSEExDjAMBgNVBAcM\n");
        cer.append("BVFVSVRPMSMwIQYDVQQKDBpQUklNRUNPUkVMQVQgUy5BLlMuIEIuSS5DLjEeMBwG\n");
        cer.append("A1UECwwVRW50ZSBkZSBDZXJ0aWZpY2FjaW9uMRwwGgYDVQQDDBNQcmltZSBDb3Jl\n");
        cer.append("IFJvb3QgQ0EyMRwwGgYDVQRhDBNWQVRFQy0xNzkzMjI0MzM5MDAxMB4XDTI2MDEz\n");
        cer.append("MDExMDUzOVoXDTM4MDEyNzExMDUzOVowgYAxCzAJBgNVBAYTAkVDMSMwIQYDVQQK\n");
        cer.append("DBpQUklNRUNPUkVMQVQgUy5BLlMuIEIuSS5DLjEeMBwGA1UEAwwVUHJpbWUgQ29y\n");
        cer.append("ZSBFbWlzb3IgQ0EyMQ4wDAYDVQQHDAVRVUlUTzEcMBoGA1UEYQwTVkFURUMtMTc5\n");
        cer.append("MzIyNDMzOTAwMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK7KYTCl\n");
        cer.append("sKg+z6RSedJnhw+8q++BcBk47hQariFhxIZgtTRmVFRnyP8Jao51W3cQPQoZg7rl\n");
        cer.append("BUPdmAMkIdz/XoDV0F31Qv04IrHf9JW4Dd69OphkugrNcyuZx7ZgF9aOrWR+S6Gt\n");
        cer.append("Sq6ovyrHE4ofsjJZo6qbO8OH22YwZhxaRCtuFk7bcKLIOT/pAdBfpPyHLJFa5rL6\n");
        cer.append("Wpke+C6GUOqeaPKWzoOv92QNrKcn35mblc4A6vTTWZObLxnDjMSwCVZDxd7SBP5e\n");
        cer.append("jqsjbhY5F8zJ7RVsEAFHtjzpJfUxMgKKGEjlUBh3iq5a+kj9fsAvkAT1KNIbGUD/\n");
        cer.append("l9pdI5O61Ns5HSZJ6/+6NbigcV/m4r8r/Fc5YqNk8DHy2yc7M39ZSKM7P/2fn5wW\n");
        cer.append("nPfywngjhNzi7lsmJozJM7XpggZm3Pb08wwCTVR+jNNCwqIv8apQcBX/hHc0Gfaf\n");
        cer.append("eEEO+DmX+1QrWbmZMD6PffyukFG4OLmVgBeMKXQ5ttX8RWwro4eh36J0Jy7JV0nl\n");
        cer.append("0kwyn9ABemIYRr1iYTSdp16CouwmcnJRj3ifWn5sxk3J1y47+RP3XPuKeg+RrJHG\n");
        cer.append("yr/2GYTINFtBNUa7jNWGQ1nXhjTZJqJuefNy655oPPS2UP4gTN2SjIwU50QJKAbX\n");
        cer.append("dGLh1L7IFGD0s+v1b6OkEIrNxLHmwheAGIITAgMBAAGjggG8MIIBuDAdBgNVHQ4E\n");
        cer.append("FgQUUqXPIPKwrYqh2LaewGW8odx7PzUwHwYDVR0jBBgwFoAUXPf7TBwpKslo9RMH\n");
        cer.append("fmw3QM4KduAwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAQYwMAYD\n");
        cer.append("VR0fBCkwJzAloCOgIYYfaHR0cDovL3BjY2EyLm9ubGluZS9jcmwvY2EyLmNybDA5\n");
        cer.append("BggrBgEFBQcBAQQtMCswKQYIKwYBBQUHMAGGHWh0dHA6Ly9wY2NhMi5vbmxpbmU6\n");
        cer.append("MzA0NC9vY3NwMB8GA1UdEQQYMBaBFGZpcm1hc0BwcmltZWNvcmUubGF0MIHDBgNV\n");
        cer.append("HSAEgbswgbgwgbUGBFUdIAAwgawwNAYIKwYBBQUHAgEWKGh0dHBzOi8vd3d3LnBy\n");
        cer.append("aW1lY29yZS5sYXQvcmVwb3NpdG9yeS9jcHMwdAYIKwYBBQUHAgIwaBpmRWwgcHJl\n");
        cer.append("c2VudGUgY2VydGlmaWNhZG8gZXMgZW1pdGlkbyBlbiBiYXNlIGEgbGFzIHBvbMOt\n");
        cer.append("dGljYXMgZGUgc2VndXJpZGFkIGRlIFBSSU1FQ09SRUxBVCBTLkEuUy4gQi5JLkMu\n");
        cer.append("MA0GCSqGSIb3DQEBCwUAA4ICAQB/bVAqCz/zNB/CWD/INu91kGTdodPjKaWx04c7\n");
        cer.append("7SehW7SQJeg6257J24jJkY24Ub2nlYPfeFha96z/RF1KZw1W0jGkthdh1OiEBgK9\n");
        cer.append("wlZ4/Q5LyENgjrS4a1eNuJjkZSLO/E4dN5t9bhk1z1moIIrqyNSBGgXdfWbeu9kL\n");
        cer.append("IWhm3220pknMTY4L+ZV/8S1c22AiFJHKhlocUkbUtvOGT64z+5c6PHzI0UDEKuZh\n");
        cer.append("KQ/KO2g9T9gYPVw35J2vGGNfSBXJR1rGvu4h2QPG5cS1E9WIO+iC/LrQyMsSUnJS\n");
        cer.append("afL4Op3dyc8LtjmDgt31IT4EFENDNG8Csjtrnkp1bOkj15mJzI6AR0/PCAkyl5Qu\n");
        cer.append("a9R1OTWiUZHOOAwa/het1w9seYRkwz2kITMNMflhZCapgpgLiAcbLc4YH835jMQ0\n");
        cer.append("glGrQAmmv8genZllhtocueFj8ycovpjKxvEod6ksR0sAK3THHrNCibNSSb2xdLwP\n");
        cer.append("YET5Tv/oXI9ACvBggHwzmE0Rdh+0JUib9HkKuNyKbfePCustCdmwB/6h/omPMBVv\n");
        cer.append("EYgsh70/LsiKweqt+x+/RK3lYZXSZ3TpaRBftJPAxwaH7uPCY1YXHC7P4rkhe9Kr\n");
        cer.append("cyRWSB8BY9t0cLyB1FJtU2u1JXOHJWeOOWheXmFjNWV11CSgDJLyuwZQhNbKgENP\n");
        cer.append("5PkqeQ==\n");
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
