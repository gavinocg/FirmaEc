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
 * Certificado raiz de Alpha Technologies CIA. LTDA, representado como un objeto
 * <code>X509Certificate</code>.
 *
 * @author Alpha Technologies Cia. Ltda.
 */
public class AlphaTechnologiesCaCert20242034 extends X509Certificate {

    private final X509Certificate certificate;

    public AlphaTechnologiesCaCert20242034() {
        super();

        StringBuilder cer = new StringBuilder();
        cer.append("-----BEGIN CERTIFICATE-----\n");
        cer.append("MIIEPzCCAyegAwIBAgIRAIJOgNfL35zMFziqA7cGgc8wDQYJKoZIhvcNAQELBQAw\n");
        cer.append("gbgxCzAJBgNVBAYTAkVDMRIwEAYDVQQIEwlQaWNoaW5jaGExDjAMBgNVBAcTBVF1\n");
        cer.append("aXRvMSYwJAYDVQQKEx1BbHBoYSBUZWNobm9sb2dpZXMgQ2lhLiBMdGRhLjEzMDEG\n");
        cer.append("A1UECxMqRW50aWRhZCBEZSBDZXJ0aWZpY2FjaW9uIERlIEluZm9ybWFjaW9uIEF0\n");
        cer.append("MSgwJgYDVQQDEx9BbHBoYSBUZWNobm9sb2dpZXMgUm9vdCBDQSAyMDI0MB4XDTI0\n");
        cer.append("MTEyMDAzMTUxOFoXDTM0MTEyMDAwMDAwMFowgbgxCzAJBgNVBAYTAkVDMRIwEAYD\n");
        cer.append("VQQIEwlQaWNoaW5jaGExDjAMBgNVBAcTBVF1aXRvMSYwJAYDVQQKEx1BbHBoYSBU\n");
        cer.append("ZWNobm9sb2dpZXMgQ2lhLiBMdGRhLjEzMDEGA1UECxMqRW50aWRhZCBEZSBDZXJ0\n");
        cer.append("aWZpY2FjaW9uIERlIEluZm9ybWFjaW9uIEF0MSgwJgYDVQQDEx9BbHBoYSBUZWNo\n");
        cer.append("bm9sb2dpZXMgUm9vdCBDQSAyMDI0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB\n");
        cer.append("CgKCAQEA+lZeH4UP12KYUHD58wOUeLFbTGBrdD48jWyz7j1tZWtUfmpq9mvQ7z8e\n");
        cer.append("wra7I31lg++FUT3sKscRleNMSuUR+NGlpVjJYW7roaCNCqFS3cMdRAQzhXlpQN0p\n");
        cer.append("Uo5Z2zUYpN1lqnVaiN/BQ31J/1u7LPty4VKWzfoUMsxNYtKQVSrFuaTeWZA8o8au\n");
        cer.append("0ZgnU9+d2ejPAMh1ysLdivlNjJmZzu9Y60d4J1mCxycbycWhvA2WjKjjEIKph6UH\n");
        cer.append("k5rRGRbtONskuV/bCBT+Eouwg81Yrc1Pt38dlG0BUyMuG1geFGYWGqckWp8zQt4h\n");
        cer.append("7PvMsW/ykMeylM+1eqnfKTY1LFRMOwIDAQABo0IwQDAOBgNVHQ8BAf8EBAMCAYYw\n");
        cer.append("DwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUmIL7Nmtixp+gtRd+ZI5l5YyvSnsw\n");
        cer.append("DQYJKoZIhvcNAQELBQADggEBAMMNsSOgzEGrZqsu4SxD6ZEymV17N40wjkLA8Ydi\n");
        cer.append("xfw6SRdlAz1ZThVd8bZd/JmllCoPTZrXson+QoAHE5cifhS45woZjLWMV87P3C6n\n");
        cer.append("DjZoMbvESLK0opaoTi9xGxfMBsrniQ08tfKNWuKnZavSvGsHOeIO8pdrkT36XGMo\n");
        cer.append("ddIO2bVWQSm8mgfF5TRPMsBmlioQ65JLMwWx9pbRYGnYwOXI+xMZymKMSpz7ATLt\n");
        cer.append("yvVQUEUisJvz/6xx3FPlfWNce5EijRvUzRYr2pS1pJFlUOyv4eUZhQHmLToNgVZ4\n");
        cer.append("SiSIXZhdXlqUt/i4KjFM3upLgRi0iSjpJbW8Wp+i2+kuBmI=\n");
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
