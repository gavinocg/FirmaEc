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
public class PrimeCoreLatCa2Cert extends X509Certificate {

    private X509Certificate certificate;

    public PrimeCoreLatCa2Cert() {
        super();

        StringBuilder cer = new StringBuilder();
        cer.append("-----BEGIN CERTIFICATE-----\n");
        cer.append("MIIHdzCCBV+gAwIBAgIUYULxZxrQodqQMNbR/fF8NfdsOHEwDQYJKoZIhvcNAQEL\n");
        cer.append("BQAwgbIxCzAJBgNVBAYTAkVDMRIwEAYDVQQIDAlQSUNISU5DSEExDjAMBgNVBAcM\n");
        cer.append("BVFVSVRPMSMwIQYDVQQKDBpQUklNRUNPUkVMQVQgUy5BLlMuIEIuSS5DLjEeMBwG\n");
        cer.append("A1UECwwVRW50ZSBkZSBDZXJ0aWZpY2FjaW9uMRwwGgYDVQQDDBNQcmltZSBDb3Jl\n");
        cer.append("IFJvb3QgQ0EyMRwwGgYDVQRhDBNWQVRFQy0xNzkzMjI0MzM5MDAxMB4XDTI2MDEz\n");
        cer.append("MDExMDUxNloXDTM4MDEyNzExMDUxNlowgbIxCzAJBgNVBAYTAkVDMRIwEAYDVQQI\n");
        cer.append("DAlQSUNISU5DSEExDjAMBgNVBAcMBVFVSVRPMSMwIQYDVQQKDBpQUklNRUNPUkVM\n");
        cer.append("QVQgUy5BLlMuIEIuSS5DLjEeMBwGA1UECwwVRW50ZSBkZSBDZXJ0aWZpY2FjaW9u\n");
        cer.append("MRwwGgYDVQQDDBNQcmltZSBDb3JlIFJvb3QgQ0EyMRwwGgYDVQRhDBNWQVRFQy0x\n");
        cer.append("NzkzMjI0MzM5MDAxMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEApChh\n");
        cer.append("6XcTrItx570j7MXnHMuHSj8P8OvyZz+UE8aoVgIFQuetgAQCXd0P810XTF1lGT5I\n");
        cer.append("mmoU1z7Gst+vQ2Uq/eukMp8GVDg0IWBc41Iso3osNwZiqinBygcfGYeesWyI5qeB\n");
        cer.append("EuiafIm1yVYoYr7GZE2dQsvPNr0v3+MQLf0r4GaqpkfZru1YPU0FeaelEUUYfmgS\n");
        cer.append("jLYCuDYoN7HtrgPrFgFwgfxgnTvE4V73866Uyvw7e3dTmInPbJew3qhyu0Fmz16U\n");
        cer.append("de4KIezwMj++aY4rKOM3KnIHguQUyQZrBNMjGhtJIqW6dU1qMZ8GNPQGcQpcIVW5\n");
        cer.append("spgifELl6DlrUWB4u+np7sYdqcOMz+VN11lG4bF4iDSpNBqAJ7btjO3rSBUuvejV\n");
        cer.append("TdU/Y/aTcQkAQSff8TU89GznrNgCP7CxhuUJoaVf+nephLNFme0r2j1F0madeWVy\n");
        cer.append("85KL0qmZqsmQf9F9P9Mk5s5FIniaWnAZ4EB0XFrF5fmozOrrdiE95Txzp4p6RsJf\n");
        cer.append("LqN+qqvVE+knDM0OnlljUz9UAP4N6pieUF7QoA8ck3ZD0UQH23RS4kpN5CvV32f7\n");
        cer.append("Ffu2Z8dnah7F1LGwUBwWfBNk7G9tVGCqmwiq4xsUjTYd751xzCR7z3/CK+kFmkfN\n");
        cer.append("FsE58L+bRnChdm9T5B5+prxYCNFI/pLzQRX7jsUCAwEAAaOCAYEwggF9MB0GA1Ud\n");
        cer.append("DgQWBBRc9/tMHCkqyWj1Ewd+bDdAzgp24DAfBgNVHSMEGDAWgBRc9/tMHCkqyWj1\n");
        cer.append("Ewd+bDdAzgp24DAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBAjAw\n");
        cer.append("BgNVHR8EKTAnMCWgI6Ahhh9odHRwOi8vcGNjYTIub25saW5lL2NybC9jYTIuY3Js\n");
        cer.append("MIHDBgNVHSAEgbswgbgwgbUGBFUdIAAwgawwNAYIKwYBBQUHAgEWKGh0dHBzOi8v\n");
        cer.append("d3d3LnByaW1lY29yZS5sYXQvcmVwb3NpdG9yeS9jcHMwdAYIKwYBBQUHAgIwaBpm\n");
        cer.append("RWwgcHJlc2VudGUgY2VydGlmaWNhZG8gZXMgZW1pdGlkbyBlbiBiYXNlIGEgbGFz\n");
        cer.append("IHBvbMOtdGljYXMgZGUgc2VndXJpZGFkIGRlIFBSSU1FQ09SRUxBVCBTLkEuUy4g\n");
        cer.append("Qi5JLkMuMB8GA1UdEQQYMBaBFGZpcm1hc0BwcmltZWNvcmUubGF0MA0GCSqGSIb3\n");
        cer.append("DQEBCwUAA4ICAQBIpLf3Gn+jhCfZvntKuj99oom7eS5860CSC610W8ewR8+HxB0+\n");
        cer.append("71g6EKSeYidBK4AypTYbffO8MVky4hHIxnDCN2vbGvQWkr2C7O8pnQ6EHMf72JrH\n");
        cer.append("s9HT641ofEYplWO3UzuxYU4veicScOWvU8jqjBUohVSxI2L7edE4iXyrNWeUYRAV\n");
        cer.append("JuJmbTpI3WC2Y2TSNGredTYbFBX3oupNa7G9jfjZQ4GoIPSL6nwPlUrIRlsGVbbK\n");
        cer.append("6r9kzOgNGXiQJp3R6wzJZ1uOdACguZp5MQp/jKsp7Ir7X/O0WVAHnf+x0gCOYLl6\n");
        cer.append("i7DmDlbGopXBREkzNFcy9CBBmgQiwSR728J21R2b+rTEAmXKm3iRzT7zSwzj4H7m\n");
        cer.append("S/vvNHkYBgLsQoCfZrp/cQA7Bw6ZgW7bESDT411+vkMnJ7sW5afe++n8y8mZl31C\n");
        cer.append("en60Ze0kk3uxcm9qdbrxXxQJed6YXPaC+GnSSIdGQheOgr9oCilwid9N6xoRRLAd\n");
        cer.append("abjz0leQsIpxY7BxpgmvBPAsEwAatOXFbuK5d5XUx//eYVEPZkhjed5cujuLH6MZ\n");
        cer.append("oSM7n9FJr7E3VO7M0mVsKwPn2pw7ZYeni+juMLnOPpNIxBpUZYHk6fAnh0UQOwpy\n");
        cer.append("UVm1WwwWMtStBdyWKWywDzewU60KSDhcGKlOzJjFMkQ7tBm212GmtrKoPA==\n");
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
