/*
 * Copyright (C) 2024
 * Authors: Mauricio Perez
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
package ec.gob.firmadigital.libreria.certificate.ec.firmasegura;

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
 * Certificado intermedio del Firmasegura S.A.S., representado como un objeto
 * <code>X509Certificate</code>.
 *
 * @author Mauricio Perez <mauricio.perez@firmaseguraec.com>
 */
public class FirmaSeguraSubCaCert20232043 extends X509Certificate {

    private X509Certificate certificate;

    public FirmaSeguraSubCaCert20232043() {
        super();

        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append("-----BEGIN CERTIFICATE-----\n");
        stringBuilder.append("MIIG2jCCBMKgAwIBAgIRANENxvt2cGDs48lXyJas6kEwDQYJKoZIhvcNAQELBQAw\n");
        stringBuilder.append("gcQxCzAJBgNVBAYTAkVDMRswGQYDVQQKDBJGSVJNQVNFR1VSQSBTLkEuUy4xMDAu\n");
        stringBuilder.append("BgNVBAsMJ0VOVElEQUQgREUgQ0VSVElGSUNBQ0lPTiBERSBJTkZPUk1BQ0lPTjET\n");
        stringBuilder.append("MBEGA1UECAwKVFVOR1VSQUhVQTFAMD4GA1UEAww3QVVUT1JJREFEIERFIENFUlRJ\n");
        stringBuilder.append("RklDQUNJT04gUkFJWiBDQS0xIEZJUk1BU0VHVVJBIFMuQS5TLjEPMA0GA1UEBwwG\n");
        stringBuilder.append("QU1CQVRPMB4XDTI0MDIyMTE4MjcxMFoXDTQzMTIyMDE5MjYxMlowgcIxCzAJBgNV\n");
        stringBuilder.append("BAYTAkVDMRswGQYDVQQKDBJGSVJNQVNFR1VSQSBTLkEuUy4xMDAuBgNVBAsMJ0VO\n");
        stringBuilder.append("VElEQUQgREUgQ0VSVElGSUNBQ0lPTiBERSBJTkZPUk1BQ0lPTjETMBEGA1UECAwK\n");
        stringBuilder.append("VFVOR1VSQUhVQTE+MDwGA1UEAww1QVVUT1JJREFEIERFIENFUlRJRklDQUNJT04g\n");
        stringBuilder.append("U1VCQ0EtMSBGSVJNQVNFR1VSQSBTLkEuUy4xDzANBgNVBAcMBkFNQkFUTzCCAiIw\n");
        stringBuilder.append("DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALPVPM8X7l/IlZT+rGnN8y2MuSpy\n");
        stringBuilder.append("QiENKHy+sAtrOgpE6JaA9S6L4M4KlsL5va2isWl9+Q8ogp2K8rjpHyjNGB2jpPd6\n");
        stringBuilder.append("3HaAJ0K/zZ6KqzdRIX35EtS0X1IgUSFkssCwG8AIKpSWvkjoWpGlN1TlTl0U6IBL\n");
        stringBuilder.append("B282DmkHGHm4Fah9C8m7uHkZakeAvOt6S+oKgxEqcopkZHvqs/C/NVn1u/JSblDV\n");
        stringBuilder.append("7tBrDga9b1ejvkErokczE1f/vDSMYO2hJ+3LHtHnQEiKUOP0k1CDcDmP/KglXXH5\n");
        stringBuilder.append("KVdoMOrBgkwPqijNnIRabguohcMvrndR8nUKCbpuciapmrSuevF4ZLUFavZyk/Wg\n");
        stringBuilder.append("iBbJiKtpYtpZZok4N01oJhAqB1zN4jJ/LuOnKmH0EVe0swvpl+TjJ2sptSW9qyF+\n");
        stringBuilder.append("tx781Z0eEJoVcj1vuPOowjzpVEkCcmXgUQWtoiXyyWJOEjvebhB2RPiXXIjORU0I\n");
        stringBuilder.append("utlDyEIxwedI0iwlSM8E9uTM9/kgqXDsvvrDNY/nt3Jv1Z0rQpfgvIoqYeb8Q3Ll\n");
        stringBuilder.append("NDV2q1ro1u76u7lpg4/P3Y9v2rp8l5hO2S8C6DReBv0q1lC6WF2gQTfKPtUtu1Y+\n");
        stringBuilder.append("7ZMQM85jzCu4lBLLQE1jCnkeGwZ31SQPLAYYor40MtgqlMj5gCBRrWWVJGVH7tad\n");
        stringBuilder.append("GYgqmV5zC/u+QUbRAgMBAAGjgcYwgcMwEgYDVR0TAQH/BAgwBgEB/wIBADAfBgNV\n");
        stringBuilder.append("HSMEGDAWgBQTdA7zmi1y+izHptdu3sIgj3rQMzAdBgNVHQ4EFgQUE0aTaAmu1ySH\n");
        stringBuilder.append("M0VjJnffrF5eilEwDgYDVR0PAQH/BAQDAgGGMF0GA1UdHwRWMFQwUqBQoE6GTGh0\n");
        stringBuilder.append("dHA6Ly9jYS1jcmwuZmlybWFzZWd1cmFlYy5jb20vY3JsLzc1MjliOTVjLTk4Yzkt\n");
        stringBuilder.append("NGJlYy04NGRlLTU1Y2Y0YjhhNzAwZi5jcmwwDQYJKoZIhvcNAQELBQADggIBAKUy\n");
        stringBuilder.append("39H37hPR0eAa2fNcjKZyDG56eTI3x+7KQ7n96jge8o39SqH1/ZZz5tNm1O4gDFVa\n");
        stringBuilder.append("IIrU1pis9+eagx4VtoMy7oL/weUPaje5fuOe7yT0iT2JpnfAJb+7OjXxEc/31G1k\n");
        stringBuilder.append("G/dWONFWGZ4rr9tbP8e1xx4QbkE6a2RU5iJKsrXCrk6K/fr19re7Fjr9hzWdXXww\n");
        stringBuilder.append("Hc9erG7LdEH26Su9Qk4hRKH4Cbfk++ZiOFpehvK1tJ9n+3nW1ujJVPAP/BvJ3ftx\n");
        stringBuilder.append("oVWSWNH8oUa6gDxrtJDt4dHPcp9wJgGYYR5ee8XV+JPcxGTkngkkVmmQ9D1KCWlF\n");
        stringBuilder.append("GQ7MWqjGWkCexKFepU4YNzZ5PrSIPxkG5vxoSw07KxLP6GPaUtfWFjN+IC8a/SKX\n");
        stringBuilder.append("gwHdmPJJaVrKUFvT7/jh3RI/uG/YhRMe0uM5GAyJChQ3Phkn/TA2AhB31z5Lrnq1\n");
        stringBuilder.append("G6X7qav/+iOUqoOYfMKB8tlWp4/gz20bx5W0XtTjg2jrzOrkOC8gD4oHnuN83BV9\n");
        stringBuilder.append("vsUAwHViEZsFaYgJtcpA+LLf/4OjmKAlPbnxPUBrJTNV0j2s+MH1FrLRZz7pZpgt\n");
        stringBuilder.append("qJLMf/aDjjubQ6taPTcHjxGhcTAgmL1J5/7/lVCYMir43FAPUchbq5k1BdsZsSsh\n");
        stringBuilder.append("qPKU+bM0H9Btm86PyPnoWC6P23Rxky+LXFPT6+4B\n");
        stringBuilder.append("-----END CERTIFICATE-----\n");

        try {
            InputStream is = new ByteArrayInputStream(stringBuilder.toString().getBytes("UTF-8"));
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
