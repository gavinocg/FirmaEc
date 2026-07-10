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
public class LazzateSubCaWeGoCert extends X509Certificate {

    private X509Certificate certificate;

    public LazzateSubCaWeGoCert() {
        super();

        StringBuilder cer = new StringBuilder();
        cer.append("-----BEGIN CERTIFICATE-----\n");
        cer.append("MIIEUTCCAzmgAwIBAgIURvxE/imz7Nqq7hjR0b0Rvik5vtMwDQYJKoZIhvcNAQEL\n");
        cer.append("BQAwgZAxCzAJBgNVBAYTAkVDMRIwEAYDVQQIDAlQSUNISU5DSEExDjAMBgNVBAcM\n");
        cer.append("BVFVSVRPMRswGQYDVQQKDBJMYXp6YXRlIENpYS4gTHRkYS4xFjAUBgNVBAsMDVdF\n");
        cer.append("LUdPIExBWlpBVEUxKDAmBgNVBAMMH1dFLUdPIFRFUkNFUiBWSU5DVUxBRE8gUm9v\n");
        cer.append("dCBDQTEwIBcNMjQwMzA3MTI1NDEwWhgPMjA1NDAyMjgxMjU0MTBaMFYxCzAJBgNV\n");
        cer.append("BAYTAkVDMRswGQYDVQQKDBJMYXp6YXRlIENpYS4gTHRkYS4xKjAoBgNVBAMMIVdF\n");
        cer.append("LUdPIFRFUkNFUiBWSU5DVUxBRE8gRW1pc29yIENBMTCCASIwDQYJKoZIhvcNAQEB\n");
        cer.append("BQADggEPADCCAQoCggEBAMNiS0eHBb9xBDm6T82Kopif7hRSwDQ8uR57Tj5MN3iA\n");
        cer.append("pC0pIUXQB5z+r9jgfLN+SXRSWITkIliT9ORcbwum/czZ2FKzqMqCbFpO+9ERQV0y\n");
        cer.append("q/7GxmyIRyc549Iz3JaYKED+FPnk+t3G2pqk0YN7FnnO4MJkTMIxS3QIdaQP0Bbs\n");
        cer.append("ea+kK3rDzBUklexQE8ymGsrvUr6wuTPunYDjm4anFsa5+MwCzCxA9Q4omEcqeX0Q\n");
        cer.append("iubX7xYMTfxfi/zk8Qzf04h5ciweUC5oMK8rJwBUHi9p5/uk+GowAfPl4m74C0T5\n");
        cer.append("5hXXi1z8TScPpgPtvQHAgQgA2bfjyNscny8NqdKnhN8CAwEAAaOB2TCB1jAdBgNV\n");
        cer.append("HQ4EFgQU1SLDtuGQ22FwlSta8rjoJi6vTCUwHwYDVR0jBBgwFoAU5OY25oY6xCPc\n");
        cer.append("VdzWvZMpeOal0rwwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYw\n");
        cer.append("MwYDVR0fBCwwKjAooCagJIYiaHR0cDovL3dlLWdvLnh5ei9jcmwvZW1pc29yQ0Ex\n");
        cer.append("LmNybDA7BggrBgEFBQcBAQQvMC0wKwYIKwYBBQUHMAGGH2h0dHA6Ly93ZS1nby54\n");
        cer.append("eXo6ODc3Ny9hZHNzL29jc3AwDQYJKoZIhvcNAQELBQADggEBAAmPa1aFzF4T/xJX\n");
        cer.append("AU17eOx7tHJBm+oRGOdm79511sDq/vu04jQJ5Fkn3K+/+YFCCbZ/TZH8AlI5GmU0\n");
        cer.append("Ygqc9ptikwXIFkAbhyB1RB8Cqel4az/smK0HrtQ73jtca/4njEguKWWou3LoBA2E\n");
        cer.append("Ytg2e7qe9A9EPkADpzggCMEsVi7XBuUHnbQbR83e1FQkU4gnAMQZhuBlEWtR3wdP\n");
        cer.append("+yMg5q0q2SASBqIP7ZF0ZaTNJGoipViVS0poj2tkGzqHYHTIlReZcK72HJq/Xbv+\n");
        cer.append("CdLYhdlUBdwUly8VWyCm38T7tNvHaE6y2AOa5s9rOLxFzUHsFDDDTgpWepmLuozR\n");
        cer.append("vabtpSA=\n");
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
