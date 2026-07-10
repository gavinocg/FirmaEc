/*
 * Copyright (C) 2026
 * Authors: DARKCAM S.A.
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
package ec.gob.firmadigital.libreria.certificate.ec.darkcam;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.util.Date;
import java.util.Set;

/**
 * Certificado subordinado de DARKCAM S.A. para certificados Short-Lived (SubCA
 * Short), representado como un objeto <code>X509Certificate</code>.
 *
 * Este SubCA se utiliza para emitir certificados de corta duración (short-lived
 * certificates) que típicamente tienen validez de horas o días, diseñados para
 * escenarios "one-shot" donde no se requiere revocación tradicional.
 *
 * @author DARKCAM S.A.
 */
public class DarkcamSubCaShortCert20262036 extends X509Certificate {

    private final X509Certificate certificate;

    public DarkcamSubCaShortCert20262036() {
        super();

        StringBuilder cer = new StringBuilder();
        cer.append("-----BEGIN CERTIFICATE-----\n");
        cer.append("MIIHkDCCBXigAwIBAgIQNsfH579+q6bcaJcnPN+fxjANBgkqhkiG9w0BAQsFADBo\n");
        cer.append("MQswCQYDVQQGEwJFQzEVMBMGA1UECgwMREFSS0NBTSBTLkEuMQwwCgYDVQQLDANQ\n");
        cer.append("S0kxEjAQBgNVBAgMCVBpY2hpbmNoYTEQMA4GA1UEAwwHQ0EgUm9vdDEOMAwGA1UE\n");
        cer.append("BwwFUXVpdG8wHhcNMjYwMTI5MjM1MDMzWhcNMzYwMTMwMDA1MDMyWjCBojELMAkG\n");
        cer.append("A1UEBhMCRUMxFTATBgNVBAoMDERBUktDQU0gUy5BLjEqMCgGA1UECwwhQ0EgRW1p\n");
        cer.append("c29yYSBkZSBDZXJ0aWZpY2FjaW9uIFNob3J0MRIwEAYDVQQIDAlQaWNoaW5jaGEx\n");
        cer.append("LDAqBgNVBAMMI0RBUktDQU0gUy5BLiAtIENBIFN1Ym9yZGluYWRhIFNob3J0MQ4w\n");
        cer.append("DAYDVQQHDAVRdWl0bzCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAJqp\n");
        cer.append("kAtoWjGqtnIiGuK/SCwJSJCW2JjvYqSRbF7bOEE8+xEWGbmvaZSQpiH5n3ONKgPN\n");
        cer.append("9aMu/AeLWaOWfUXxljynRVb0kMdEONYfqff58+yvI8aL2+R5rlYPJKIv5N+lmNGN\n");
        cer.append("qkN39HXMp+FiNNf87RqR4IYRdl/bRVbWeWBki1qwFY8KcvRkwADE97YrOZkT03bL\n");
        cer.append("E2zvFO7teD6Gv3cpiTh2g5cgO6ot/sb/QEblFeXpHCHQmZjDzxmYD1kAk3ehU5a+\n");
        cer.append("xDRNShN757/ogfXz832lhaK2EgwbllvU+HkwL8IegFQVAgVdPNazYdJsOBU43s3W\n");
        cer.append("ZMypurHYgvPmQzYclU/Jiao8r0P/JkmOkkvLlqGv2oSTibs+qBZYWnkv40lkst/O\n");
        cer.append("6KLb4y9FB65UT9/wSjEzAdPTaX9VXk7ahhq78PlnrszNroCE+kpvc6hm2OhKicC/\n");
        cer.append("//MZOkKOYs32H43jx3UX/qRgCkHX4Kbhzv3WM6tzTn+BInYq9YlASMU19BPpqrVf\n");
        cer.append("HRs4Nk1nnRcN5mFoIF2Ono74vrzcmBEohDdy9EiJMcaYRGKH9kbNWnNJReSYUDnn\n");
        cer.append("Q9x8VkbRjns1y8PQuwhuyUKF0Tum7tSeaBE/U0tp2Jhu0Ea5udwkCEd7K33KExTm\n");
        cer.append("+VA3gdE2wZYUnYLUieup4tyBJf4TXNXBiZEAl/zFAgMBAAGjggH5MIIB9TASBgNV\n");
        cer.append("HRMBAf8ECDAGAQH/AgEAMB8GA1UdIwQYMBaAFBCE3RAEUJNqKXzLYFOTD1k107fL\n");
        cer.append("MB0GA1UdDgQWBBRL9SSVRcnKc3ihpYBouYoG/Ur/lTAOBgNVHQ8BAf8EBAMCAYYw\n");
        cer.append("JgYDVR0RBB8wHYEbYWRtaW5pc3RyYXRpdm9AZGFyay1jYW0uY29tMIGCBgNVHR8E\n");
        cer.append("ezB5MHegdaBzhnFodHRwOi8vY2Etcm9vdC1jcmwtZGFya2NhbS12Mi5zMy51cy1l\n");
        cer.append("YXN0LTEuYW1hem9uYXdzLmNvbS9jcmwvY2M4NWRiNWEtN2UyNC00M2FkLWE4NzMt\n");
        cer.append("NGM1YjAyMTBhNzUzL0VvTklaYmpBOXRkLmNybDBHBggrBgEFBQcBAQQ7MDkwNwYI\n");
        cer.append("KwYBBQUHMAGGK2h0dHA6Ly9vY3NwLmFjbS1wY2EudXMtZWFzdC0xLmFtYXpvbmF3\n");
        cer.append("cy5jb20wgZgGA1UdIASBkDCBjTCBigYEVR0gADCBgTAzBggrBgEFBQcCARYnaHR0\n");
        cer.append("cHM6Ly91bml2ZXJzZS1pZC5jb20vZGFya2NhbS9jcHMucGRmMEoGCCsGAQUFBwIC\n");
        cer.append("MD4MPENlcnRpZmljYWRvIGVtaXRpZG8gY29uZm9ybWUgYSBsYXMgcG9saXRpY2Fz\n");
        cer.append("IGRlIERBUktDQU0gUy5BLjANBgkqhkiG9w0BAQsFAAOCAgEAcDK/I2EqYsO60qeq\n");
        cer.append("ZgtkwvFFy4aygxjomHqwrQSh0mzS8aSEBJqnqHub8K/OWkZdKvUFgObVkjHsgZTE\n");
        cer.append("66hdIXfTG+PVO+rlo79BXrAIhOrJh8Vsuz+YaKMoeMhIKm4TcXRmlLPqtyWU9B4t\n");
        cer.append("5DB/uw/kb3ScskscWyH4K5vZouYcj0Lg8UTebOKt/wNaAHFy5CK4RQUu/KTen7Yr\n");
        cer.append("w/LNdHUPtQ+WiGzhj2tyoulFoSKC+e+uNjlHrL1zFoFNByI76iS1ZoXKvV5xSE1K\n");
        cer.append("Zp3vpSFwBeh+8w1INy+PkPkMgWIS/HiqE05vewIbaVdLNPWT4Vs0CgAUbo8PBIq2\n");
        cer.append("xZBf7vMP5xlbmI//cCENdRWk93VTWiwKAg2y6qveAH3ynm1rvDYGkhqUlE5mY3Pd\n");
        cer.append("2OeoTrRnQWBr4sCdnHqaHGKxFIBHWSY/cCSk3M1hYXUQQ+Ui/PGnL6cNRSKrFg0y\n");
        cer.append("jpFwJzWwjNAry1OrLGfde1793PVLJHyqj8b0tJPvsDM38+Opz2a3ROj5UdGFj1Ex\n");
        cer.append("E8L2pTAHfp/dYubmhFrmN/4V/2PtuUN8qPc1NygXgJaqxBvpyb1sW0AGKzaNSOgA\n");
        cer.append("CRMJMKL3hQy6CdTM1nn7SgUCoIURvLz4zA48EPhwq/lEpv4+0D9Yobc7ZfrAO+9D\n");
        cer.append("pl0OY8lsibl+inz+COKvGTS7Ako=\n");
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
