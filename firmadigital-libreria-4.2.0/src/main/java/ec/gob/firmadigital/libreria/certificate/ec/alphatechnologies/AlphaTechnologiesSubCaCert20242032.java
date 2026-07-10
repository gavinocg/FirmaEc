/*
 * Copyright (C) 2025
 * Authors: Alpha Technologies Cia. Ltda.
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
package ec.gob.firmadigital.libreria.certificate.ec.alphatechnologies;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.util.Date;
import java.util.Set;

/**
 * Certificado intermedio de Alpha Technologies CIA. LTDA, representado como un
 * objeto <code>X509Certificate</code>.
 *
 * @author Alpha Technologies Cia. Ltda.
 */
public class AlphaTechnologiesSubCaCert20242032 extends X509Certificate {

    private final X509Certificate certificate;

    public AlphaTechnologiesSubCaCert20242032() {
        super();

        StringBuilder cer = new StringBuilder();
        cer.append("-----BEGIN CERTIFICATE-----\n");
        cer.append("MIIFjzCCBHegAwIBAgIRAIJOgOQmMs+CANPLRzVjJpcwDQYJKoZIhvcNAQELBQAw\n");
        cer.append("gbgxCzAJBgNVBAYTAkVDMRIwEAYDVQQIEwlQaWNoaW5jaGExDjAMBgNVBAcTBVF1\n");
        cer.append("aXRvMSYwJAYDVQQKEx1BbHBoYSBUZWNobm9sb2dpZXMgQ2lhLiBMdGRhLjEzMDEG\n");
        cer.append("A1UECxMqRW50aWRhZCBEZSBDZXJ0aWZpY2FjaW9uIERlIEluZm9ybWFjaW9uIEF0\n");
        cer.append("MSgwJgYDVQQDEx9BbHBoYSBUZWNobm9sb2dpZXMgUm9vdCBDQSAyMDI0MB4XDTI0\n");
        cer.append("MTEyMDAzMTUyOFoXDTMyMTEyMDAwMDAwMFowgcExCzAJBgNVBAYTAkVDMRIwEAYD\n");
        cer.append("VQQIEwlQaWNoaW5jaGExDjAMBgNVBAcTBVF1aXRvMSYwJAYDVQQKEx1BbHBoYSBU\n");
        cer.append("ZWNobm9sb2dpZXMgQ2lhLiBMdGRhLjEzMDEGA1UECxMqRW50aWRhZCBEZSBDZXJ0\n");
        cer.append("aWZpY2FjaW9uIERlIEluZm9ybWFjaW9uIEF0MTEwLwYDVQQDEyhBbHBoYSBUZWNo\n");
        cer.append("bm9sb2dpZXMgQXRsYXMgU2lnbmluZyBDQSAyMDI0MIIBIjANBgkqhkiG9w0BAQEF\n");
        cer.append("AAOCAQ8AMIIBCgKCAQEAtgkIAbDJbcNgVOX0gwf5L7PSDwBYCmRlh8cgW5OpQe23\n");
        cer.append("YTDOniaDBZFR0Akql15+73ns7C+ANBmDZv+H4Ns0BTRnZZTz/SdVNmw3Wvrww2My\n");
        cer.append("w8P+nMMCsHugxuR7kjKo17RBuSdn7EcP4D59o7+ulSzA/ns58936WEO/A/NcF23s\n");
        cer.append("AiSSwn4q1qUhISkn86M7PK8hlzvupxMf3o/q8zXKPaUszOvMSDY42632MB5pfqJy\n");
        cer.append("A+zPTNfkJr4H86+2usnxverV4J9e+nkxosYbosU5c72JShRicxtlUNrYuwZOwJYG\n");
        cer.append("RPJCdPEZJvlqxl6OdSm3eFn66GvtmhGFR0WnwRHgowIDAQABo4IBhzCCAYMwDgYD\n");
        cer.append("VR0PAQH/BAQDAgGGMCkGA1UdJQQiMCAGCCsGAQUFBwMCBggrBgEFBQcDBAYKKwYB\n");
        cer.append("BAGCNwoDDDASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBTp4Q/aOOgvs12C\n");
        cer.append("gW9ceoTWOnakODAfBgNVHSMEGDAWgBSYgvs2a2LGn6C1F35kjmXljK9KezCBpQYI\n");
        cer.append("KwYBBQUHAQEEgZgwgZUwQgYIKwYBBQUHMAGGNmh0dHA6Ly9vY3NwLmdsb2JhbHNp\n");
        cer.append("Z24uY29tL2FscGhhdGVjaG5vbG9naWVzcm9vdGNhMjAyNDBPBggrBgEFBQcwAoZD\n");
        cer.append("aHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvYWxwaGF0ZWNobm9s\n");
        cer.append("b2dpZXNyb290Y2EyMDI0LmNydDBKBgNVHR8EQzBBMD+gPaA7hjlodHRwOi8vY3Js\n");
        cer.append("Lmdsb2JhbHNpZ24uY29tL2FscGhhdGVjaG5vbG9naWVzcm9vdGNhMjAyNC5jcmww\n");
        cer.append("DQYJKoZIhvcNAQELBQADggEBABc8ntQ0lcm4dMJK8f9kFNPKdF8Ts7M0mX9uM9NW\n");
        cer.append("iKawDJ3a+d23hkFWPUcetKSB0uTNvQZKalX4FXywCBUMyGtAejoXmV0aAFkRPHL/\n");
        cer.append("xztevyRzs4f1cpqRuqmxHmRRP2X5adFb2MlVLKL1oMBeP6UxsAmke3oeWHxoaO0W\n");
        cer.append("tMRx9gkeFbZM46cSZ+ypVR0NvjEli4M2e1TLOKi/JiBkgfeBz6UDDi8Va5gaeLta\n");
        cer.append("9mRLzMDgVesdT5Vo5GqeaSTAHvTM8jPNmAhTlrgmvkwT+aI7HcrQ2NUNRtHVOMqv\n");
        cer.append("gjISJ7mOfBzQMAUI5SswvVMKteo2vUIEoJJ3A74Ai0W0+e8=\n");
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
