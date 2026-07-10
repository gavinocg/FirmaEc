/*
 * Copyright (C) 2026
 * Authors: Misael Fernández, DARKCAM S.A.
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
 * Certificado raiz de DARKCAM S.A., representado como un objeto
 * <code>X509Certificate</code>.
 *
 * @author DARKCAM S.A.
 */
public class DarkcamCaCert20262046 extends X509Certificate {

    private final X509Certificate certificate;

    public DarkcamCaCert20262046() {
        super();

        StringBuilder cer = new StringBuilder();
        cer.append("-----BEGIN CERTIFICATE-----\n");
        cer.append("MIIGZDCCBEygAwIBAgIQR5o4JbcaPlBCC2Ba/MeVvzANBgkqhkiG9w0BAQsFADBo\n");
        cer.append("MQswCQYDVQQGEwJFQzEVMBMGA1UECgwMREFSS0NBTSBTLkEuMQwwCgYDVQQLDANQ\n");
        cer.append("S0kxEjAQBgNVBAgMCVBpY2hpbmNoYTEQMA4GA1UEAwwHQ0EgUm9vdDEOMAwGA1UE\n");
        cer.append("BwwFUXVpdG8wHhcNMjYwMTI5MjMyNDIxWhcNNDYwMTMwMDAyNDIxWjBoMQswCQYD\n");
        cer.append("VQQGEwJFQzEVMBMGA1UECgwMREFSS0NBTSBTLkEuMQwwCgYDVQQLDANQS0kxEjAQ\n");
        cer.append("BgNVBAgMCVBpY2hpbmNoYTEQMA4GA1UEAwwHQ0EgUm9vdDEOMAwGA1UEBwwFUXVp\n");
        cer.append("dG8wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDl8jCaDGPkaveAdjFr\n");
        cer.append("iR/ERGFayXmmGxNhnzI7etKeWk1+62wQb4+laCyrdpIvulMgmUfdcddtOfKrnUHo\n");
        cer.append("XiEdlfN4YcBzY1WdKrSJYvUtQpxL9+/uxyaeMbTv6q9IvqJUnI1L+x9scM9XgKn0\n");
        cer.append("Kmvr+B606YuKgvgr3ctk1lDvJWjyg2d46289nwl9eodO5geuBMA1CHOhsKwJdgER\n");
        cer.append("sksgup7x8t3qvw3RfmmGitRMRKZK7lfyW1HsbgC8LHF/T1hVM0zQuezYi/qrcc23\n");
        cer.append("0hqYHjxSvIs5GQfUTY1q32mfSBWfFpI5RDkhgtp6Y5RVtG8fYys3n6uMWdLt4wgv\n");
        cer.append("i1C4mct6GUeJnOYOCDX4JYSp2AEjLTxeEv3EjUOI77vEwhmDLHpKucvYXCYGNGai\n");
        cer.append("6272W9FHJP14LUrIyuMWYf6ssCIPs2rT9Tlxz8uAy6ZIa4+/sBcRM5zl9dJPL9CC\n");
        cer.append("4PLfSmqNen9WmDrkajq9pWop6Od4plp3YzLJb+u8dmzDuBP94c4gGl5KU8rzr7zP\n");
        cer.append("tG/fAFS4+WDa6Bi/2a1umQaS+T2MHr4enFgg1FT62XIfp7u0CnzMXb16CxdI+NIV\n");
        cer.append("8Z6f0gpcXaFxDzG3+CBVysJduV6JyBmWhUBxxl/EP6tSWzLRZLL1uGF95G943KCl\n");
        cer.append("r781V70obxjTaIJBciWf3B9QxQIDAQABo4IBCDCCAQQwDwYDVR0TAQH/BAUwAwEB\n");
        cer.append("/zAdBgNVHQ4EFgQUEITdEARQk2opfMtgU5MPWTXTt8swDwYDVR0PAQH/BAUDAweG\n");
        cer.append("ADAmBgNVHREEHzAdgRthZG1pbmlzdHJhdGl2b0BkYXJrLWNhbS5jb20wgZgGA1Ud\n");
        cer.append("IASBkDCBjTCBigYEVR0gADCBgTAzBggrBgEFBQcCARYnaHR0cHM6Ly91bml2ZXJz\n");
        cer.append("ZS1pZC5jb20vZGFya2NhbS9jcHMucGRmMEoGCCsGAQUFBwICMD4MPENlcnRpZmlj\n");
        cer.append("YWRvIGVtaXRpZG8gY29uZm9ybWUgYSBsYXMgcG9saXRpY2FzIGRlIERBUktDQU0g\n");
        cer.append("Uy5BLjANBgkqhkiG9w0BAQsFAAOCAgEA36aAyY5ghA5jtYwwg0wrwwckcwn+RGXK\n");
        cer.append("xCcGefDEWDsHJ39dT73XbAuIW3bSQuwwUINsold6ApLoAFmiusAjRXfkEF6PRXuG\n");
        cer.append("HciUIDDWk1T4XX94rKlYy6OoTDBB5rIg96eP1hxPDeHPgcXEYuwdKY/ivcCxfbwL\n");
        cer.append("cp+/25FBBi7JGocZg4qSLGT54aPlWYrDJuP/MDi0gKC9plblF0ubrW9/JWX8qg7n\n");
        cer.append("CNrNVMfiEV+bx65Y8AInHG9dxVkiN+9//WiuFXNyCRBKMx4ARIS43R2csBpm3Jk/\n");
        cer.append("ksfys1LSJkE2FNJdeWFpo7liWvvclwrXJf4wJ1/+klkpzL4v5eQ9hj0k/ttxl3iK\n");
        cer.append("pPneAvLnkO47iVXBC/MV+U0NZaDXpOb5ooRqrDP526GQEsCjTo9yqPryc7EhkEAp\n");
        cer.append("Cu/aNf9LQPRzjNuCvcMZLWMEmjxIZ0mOjPgKvDFwFZWlOaQfn6B8RMnVWCKXtPkK\n");
        cer.append("dJ10OYEH2Z5tB1ebJ2cTpNOmWM/VgSV1Wz3SlKgDw5Vw6ebt224dmd1JMGFEzsjx\n");
        cer.append("ZLKkwXSu4tCEnO/LgSvNyTM0gwcTuCn5WFEi1yAkyWfeV2gpDLPB1Uw3yx4OSbTq\n");
        cer.append("kd8i5kVevD0gF1NhYFTHnWtbV/BQcWbp15B1epcEmyEwnXNl1quwGclLbhG79Fg6\n");
        cer.append("rr8mWzrRhRc=\n");
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
