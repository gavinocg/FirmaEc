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
 * Certificado intermedio de Argos Data, representado como un objeto
 * <code>X509Certificate</code>.
 *
 * @author Ricardo Arguello
 */
public class ArgosDataSubCaCert extends X509Certificate {

    private X509Certificate certificate;

    public ArgosDataSubCaCert() {
        super();

        StringBuilder cer = new StringBuilder();
        cer.append("-----BEGIN CERTIFICATE-----\n");
        cer.append("MIIEPTCCAyWgAwIBAgIQcWEMCbBndieHDITGCtpzGzANBgkqhkiG9w0BAQsFADBc\n");
        cer.append("MQswCQYDVQQGEwJFQzESMBAGA1UECgwJQXJnb3NEYXRhMRUwEwYDVQQLDAxBcmdv\n");
        cer.append("c0RhdGEgQ0ExIjAgBgNVBAMMGUFyZ29zRGF0YSBSb290IENBIC1TSEEyNTYwHhcN\n");
        cer.append("MjIwNjI0MTQzOTM1WhcNMzIwNDI0MTUzOTM1WjBaMQswCQYDVQQGEwJFQzESMBAG\n");
        cer.append("A1UECgwJQXJnb3NEYXRhMRUwEwYDVQQLDAxBcmdvc0RhdGEgQ0ExIDAeBgNVBAMM\n");
        cer.append("F0FyZ29zRGF0YSBDQSAxIC0gU0hBMjU2MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n");
        cer.append("MIIBCgKCAQEAjQr16iNt2hibMPib/J7ib/1jJJYbQp2+JeXyXJeuf7jZDYtIDo3O\n");
        cer.append("FIn4lYmG7xC4tLVhwMFJr7BqEBwqt20zoLj6P+XYxNThsfqpD/QhHs5hu69EcuNq\n");
        cer.append("GHfR2kbwupE+vPwgFmnZo9dbswExu1VrGnImn0Hf32PQBaj7i+1c20yEQCyHn7cx\n");
        cer.append("YCS0/Ie6+1FA8TcSc5O0KGZcxIB4zPRmpQoVymRqeflEWuLxrhf6P2b3cdnsCWul\n");
        cer.append("cHL9xSMVYkX9kreGWxnn8hepFbAGSR2u2tu/vPptT941s/otsJywExtLy7hFJmqS\n");
        cer.append("AwQfYrzR7ecCQbW+Lm108vcuPZiElc5TcQIDAQABo4H8MIH5MBIGA1UdEwEB/wQI\n");
        cer.append("MAYBAf8CAQAwHwYDVR0jBBgwFoAUeT/H7786cSf12ie9CQ7o/8SYDkwwHQYDVR0O\n");
        cer.append("BBYEFC16b67iTX5ifyqFyQsWxR3zSglHMA4GA1UdDwEB/wQEAwIBhjBZBgNVHR8E\n");
        cer.append("UjBQME6gTKBKhkhodHRwOi8vY3JsLmFyZ29zZGF0YS5jb20uZWMvY3JsLzk1N2U1\n");
        cer.append("NGQwLTc0NjctNDExZC1iZjAxLTk2YTZhYzdiNDI0ZS5jcmwwOAYIKwYBBQUHAQEE\n");
        cer.append("LDAqMCgGCCsGAQUFBzABhhxodHRwOi8vb2NzcC5hcmdvc2RhdGEuY29tLmVjMA0G\n");
        cer.append("CSqGSIb3DQEBCwUAA4IBAQBfI8G69laf2IhAoml5baJty/sY2EA3pNnUqIZWqpfN\n");
        cer.append("t/pEBs2RwighGb7faZY2ZEZraK0KKR+CUu8d+EJjJCCHt7rw0HKVPj6wBxY5l1VT\n");
        cer.append("gwANGJqgGoyVMKkxccCW5lnmhlF2M8Q+1DFaM4D2hqsqyJd2BM/6v49ukBXMU2wQ\n");
        cer.append("Hzf6cSn4JV8tPOKG9mCaJfiCnOsn+6qho+Etp0jXHsZ7u77yK+c2QlQ66aU0KDCO\n");
        cer.append("un9kRfE70X67r9HqHmgZF15q2RPLZzDYKph57KFJJQNB0LgiJfVcEJNphuVXLm0Z\n");
        cer.append("vUbidw52HYwxZJzM5pBxQfdNjssiziyWi8wLCoZwQsnF\n");
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
