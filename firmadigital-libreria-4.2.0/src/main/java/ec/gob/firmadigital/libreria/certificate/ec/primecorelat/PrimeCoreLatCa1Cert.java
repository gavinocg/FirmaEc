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
 * Certificado raiz de PRIMECORELAT, representado como un objeto
 * <code>X509Certificate</code>.
 *
 * @author Henry Carrera <henry@hyrserv.com>
 */
public class PrimeCoreLatCa1Cert extends X509Certificate {

    private X509Certificate certificate;

    public PrimeCoreLatCa1Cert() {
        super();

        StringBuilder cer = new StringBuilder();
        cer.append("-----BEGIN CERTIFICATE-----\n");
        cer.append("MIIHdzCCBV+gAwIBAgIUVflFa7tPxMINdLmA8aMybjBLTIkwDQYJKoZIhvcNAQEL\n");
        cer.append("BQAwgbIxCzAJBgNVBAYTAkVDMRIwEAYDVQQIDAlQSUNISU5DSEExDjAMBgNVBAcM\n");
        cer.append("BVFVSVRPMSMwIQYDVQQKDBpQUklNRUNPUkVMQVQgUy5BLlMuIEIuSS5DLjEeMBwG\n");
        cer.append("A1UECwwVRW50ZSBkZSBDZXJ0aWZpY2FjaW9uMRwwGgYDVQQDDBNQcmltZSBDb3Jl\n");
        cer.append("IFJvb3QgQ0ExMRwwGgYDVQRhDBNWQVRFQy0xNzkzMjI0MzM5MDAxMB4XDTI2MDEz\n");
        cer.append("MDExMjMzOFoXDTM4MDEyNzExMjMzOFowgbIxCzAJBgNVBAYTAkVDMRIwEAYDVQQI\n");
        cer.append("DAlQSUNISU5DSEExDjAMBgNVBAcMBVFVSVRPMSMwIQYDVQQKDBpQUklNRUNPUkVM\n");
        cer.append("QVQgUy5BLlMuIEIuSS5DLjEeMBwGA1UECwwVRW50ZSBkZSBDZXJ0aWZpY2FjaW9u\n");
        cer.append("MRwwGgYDVQQDDBNQcmltZSBDb3JlIFJvb3QgQ0ExMRwwGgYDVQRhDBNWQVRFQy0x\n");
        cer.append("NzkzMjI0MzM5MDAxMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAmJ2o\n");
        cer.append("h2FfrvTpbzqaSTdyzSB/hxJI2nWMLLDMjlPtSR7ilSwyaQ7ChvBPYXistpelHRul\n");
        cer.append("Sf0PiuM85aQWQNTaPPpuNtkaIqWrf+ATjrhb9mjgCiUPBO9OG3fAaV+VtgOPH/aa\n");
        cer.append("ygbqZkKHMMgzpGqv/rt/if9fpdDFysw5UmABEaVO6Juz7Wy/cGB167Im5N4WUE40\n");
        cer.append("giBw1c1i7nNjM3nfaxMyYVAyMfeoJXamTFXS3SKMaSz3ttFLoC30t+XIjUCcaXkj\n");
        cer.append("T30qF7OO9YQ0RXW5wV9konuh410QL5g6/u1zsHKZ3Yrd3FrZPM0cVeVcvWdeM7hz\n");
        cer.append("SfOW0OMo/I7WQmX/fhja1e+Uq4RLG4AY6KDmvlV8KTAoSHC/Vj5KPe2CW+l+vFQ9\n");
        cer.append("ka6BgOJ0h2zINa7rjR8mWoPiGRGITl55oxpHFHTqWJ2K0kazBP/BxEIRIfPt9H0I\n");
        cer.append("uajE/SFN8WJeLKKGgUbVJm3q4tqCRXHsvDn4POmbQByhZ2sxoBIXS78jGx3RBfag\n");
        cer.append("6j++zA1sHs1ANj7WyWIWLp7tLiAVvkTRmCkh6prLoGAyw7+bzuwt/vvuEGQig8Wi\n");
        cer.append("o3jcaBB+4F8tr2Ti9yPwcW7WRoRVQA4uwp0fh4h1k2s8l33Sv7J3K2ggxxGifdAN\n");
        cer.append("Z39mvu6W/gXnjthOga1heYVDI0BY6WRfqfo6uqkCAwEAAaOCAYEwggF9MB0GA1Ud\n");
        cer.append("DgQWBBSQoZEvNSBZyLAZZpfOMZG4GZTwnTAfBgNVHSMEGDAWgBSQoZEvNSBZyLAZ\n");
        cer.append("ZpfOMZG4GZTwnTAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBAjAw\n");
        cer.append("BgNVHR8EKTAnMCWgI6Ahhh9odHRwOi8vcGNjYTEub25saW5lL2NybC9jYTEuY3Js\n");
        cer.append("MIHDBgNVHSAEgbswgbgwgbUGBFUdIAAwgawwNAYIKwYBBQUHAgEWKGh0dHBzOi8v\n");
        cer.append("d3d3LnByaW1lY29yZS5sYXQvcmVwb3NpdG9yeS9jcHMwdAYIKwYBBQUHAgIwaBpm\n");
        cer.append("RWwgcHJlc2VudGUgY2VydGlmaWNhZG8gZXMgZW1pdGlkbyBlbiBiYXNlIGEgbGFz\n");
        cer.append("IHBvbMOtdGljYXMgZGUgc2VndXJpZGFkIGRlIFBSSU1FQ09SRUxBVCBTLkEuUy4g\n");
        cer.append("Qi5JLkMuMB8GA1UdEQQYMBaBFGZpcm1hc0BwcmltZWNvcmUubGF0MA0GCSqGSIb3\n");
        cer.append("DQEBCwUAA4ICAQAE2nnsWfhEFlpvP1MqVHBWY+D8lohK2g+vvDcmTksQqhh6/2lO\n");
        cer.append("3QvnqpJvqOglg230bXtwzCvLT6NnHSbv0aGjD5Gl8Ryzc/WeocTguL45ybgBaOLT\n");
        cer.append("v60o4rmXUy8Es1WiE51wdXJDySt2KSaaxTe9KFTXsecRNXGaPTaUW60acVyhosQF\n");
        cer.append("m/fDVQHTshEWYiqRkczJsgbQA3pPxKY6ncu/d9le+fnJ8kk9L5XLyxutKP4hrgJC\n");
        cer.append("QRHnYue/f0s7hXWIuBemFQXSXqh7TNEH/pkPWAtNzmlynjxHZHWWlhQBJ3iqnc3o\n");
        cer.append("o/kt56MbPQXD1li6a8S51x3FY5pg4zFPg0reIgrOFfI5syO+CKzkbY1VY8zYAglv\n");
        cer.append("u58wefOMZiahLmvbeca+5vDDPQUysHvTFlXFgPJir8gKGepau9MJr6+TNsHEb9f/\n");
        cer.append("bgsnnqXLmOB+4Or9PynT+vD6rohkQzLW4AY8ycRoVq8yOftQhP4SSFRx6Os/71dH\n");
        cer.append("+LbwKfsLnAVhU/42m3toQdBf53vy7w0bEbGQ1kL0udnlBunIkJPCM9bzFqyeKlM1\n");
        cer.append("uhXsn2EC7RxxJahQm6E5v9sl9+Ife7d+Qo6iX6FqXxm/53n4wGhNS7wsT4XlUSkw\n");
        cer.append("Ynyi7zeeotr8iwRgeggQ0bKRl9IxvFTLKkwaPyZo2ollETVlczayKALngA==\n");
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
