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
public class PrimeCoreLatSubCa1Cert extends X509Certificate {

    private X509Certificate certificate;

    public PrimeCoreLatSubCa1Cert() {
        super();

        StringBuilder cer = new StringBuilder();
        cer.append("-----BEGIN CERTIFICATE-----\n");
        cer.append("MIIHgDCCBWigAwIBAgIUBe0NDpngsl1ie6P/va55iLZoo50wDQYJKoZIhvcNAQEL\n");
        cer.append("BQAwgbIxCzAJBgNVBAYTAkVDMRIwEAYDVQQIDAlQSUNISU5DSEExDjAMBgNVBAcM\n");
        cer.append("BVFVSVRPMSMwIQYDVQQKDBpQUklNRUNPUkVMQVQgUy5BLlMuIEIuSS5DLjEeMBwG\n");
        cer.append("A1UECwwVRW50ZSBkZSBDZXJ0aWZpY2FjaW9uMRwwGgYDVQQDDBNQcmltZSBDb3Jl\n");
        cer.append("IFJvb3QgQ0ExMRwwGgYDVQRhDBNWQVRFQy0xNzkzMjI0MzM5MDAxMB4XDTI2MDEz\n");
        cer.append("MDExMjUzOVoXDTM4MDEyNzExMjUzOVowgYAxCzAJBgNVBAYTAkVDMSMwIQYDVQQK\n");
        cer.append("DBpQUklNRUNPUkVMQVQgUy5BLlMuIEIuSS5DLjEeMBwGA1UEAwwVUHJpbWUgQ29y\n");
        cer.append("ZSBFbWlzb3IgQ0ExMQ4wDAYDVQQHDAVRVUlUTzEcMBoGA1UEYQwTVkFURUMtMTc5\n");
        cer.append("MzIyNDMzOTAwMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALMZXiHV\n");
        cer.append("Fp+TT5cHVAadzWAQgw+wkohUlgHB7JtmX1rRbNhlwkBceXC6tgHzzTD0sXKBq/rR\n");
        cer.append("z0ITpqwYqncZ8g4pbL/qTPQjqDvekVrlo49Eq5XisQMZ9VYEvQRKhrhBVwL4QyII\n");
        cer.append("YpYF+HUdZG19SbbAKqcfm+5JHLDi0kD0MA3my/7zVtdqOnB8L7t1VHAdLB5c8UlS\n");
        cer.append("MDHcK+Ebc/gjCtWRmc1qsLICAOUoe23tVW/07ZwbY6sgCrqhrUogPw2aAJky+qPR\n");
        cer.append("qvVNbClZBKFHJiOxwL04Hz9+mmmlHAlLI/AtuFO/GxOou8SqXx+TyaJ/MyEQlveu\n");
        cer.append("m3Gx2+2P7RpyAYrgTYplh+BtO7qxw8E4WJqxEpKd9b/xRoeRM8FUZBAh73zQj3Ml\n");
        cer.append("gh/VJE63t0J1rwTsUd4HQn4BCHeta+NPA5R+Hr+FIjIbaOHJT17aR69iLr5QZjGq\n");
        cer.append("Jm3OuZ4uiH/e2h3UE9jPhsT+uixradbJgtp2PVQIi8mIg/0QrYgkuPxDltM0wg+o\n");
        cer.append("s9tvf6nYrTUy7Rinkq/ssDOgoxfpajxjt3ph+2hVUeix08DRN94mn1IJXYEuM3Vy\n");
        cer.append("2c28CnKnzBXQBlFfiwSANAtSKBJTdlwTtXTNerKyGBws7Y/Jyf0H+mCkYVgyZZpS\n");
        cer.append("2R60fH6uAzZi9OL2SY4C0kE9PPKny7JC4CTpAgMBAAGjggG8MIIBuDAdBgNVHQ4E\n");
        cer.append("FgQU3xe3XdFolZSs2hBPv3KWvdJX7ecwHwYDVR0jBBgwFoAUkKGRLzUgWciwGWaX\n");
        cer.append("zjGRuBmU8J0wEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAQYwMAYD\n");
        cer.append("VR0fBCkwJzAloCOgIYYfaHR0cDovL3BjY2ExLm9ubGluZS9jcmwvY2ExLmNybDA5\n");
        cer.append("BggrBgEFBQcBAQQtMCswKQYIKwYBBQUHMAGGHWh0dHA6Ly9wY2NhMS5vbmxpbmU6\n");
        cer.append("MzA0NC9vY3NwMB8GA1UdEQQYMBaBFGZpcm1hc0BwcmltZWNvcmUubGF0MIHDBgNV\n");
        cer.append("HSAEgbswgbgwgbUGBFUdIAAwgawwNAYIKwYBBQUHAgEWKGh0dHBzOi8vd3d3LnBy\n");
        cer.append("aW1lY29yZS5sYXQvcmVwb3NpdG9yeS9jcHMwdAYIKwYBBQUHAgIwaBpmRWwgcHJl\n");
        cer.append("c2VudGUgY2VydGlmaWNhZG8gZXMgZW1pdGlkbyBlbiBiYXNlIGEgbGFzIHBvbMOt\n");
        cer.append("dGljYXMgZGUgc2VndXJpZGFkIGRlIFBSSU1FQ09SRUxBVCBTLkEuUy4gQi5JLkMu\n");
        cer.append("MA0GCSqGSIb3DQEBCwUAA4ICAQB9W88Cu2oCzvC9ABqoqjc7pw2CCmht37ai4Hvj\n");
        cer.append("z62MAJBhwVScmfV8mvSXA7IPpknKCldN3+zvdpaH9wVeqBLKf+dLFG5bcl8T7ocd\n");
        cer.append("Lyhske0aunVYOhhSdmpAwxlEb/EhDtBl5SM0YSVoAOoS7Zakqun9xcHuKB9tgHbV\n");
        cer.append("qZz/JPD1/mshADPpRMVZkvApHHnkI+1rrJnIFGJGcBNaA8bRSDuhMzG3g7c9OGtd\n");
        cer.append("iYG26wPU+qyllFWUdx/+yWWMwx7/tlLAYm7aZ1fGHdcv5eiWRlLruXZMBpcAfUub\n");
        cer.append("mCBxA5feHaktL7f7koqeFydYudBqU81sZC/HWg1mwDg17raxlqFAGRun1n0YivHX\n");
        cer.append("XBrNJAGZgfGUaQP+9YruOeBUGmepIerU8NcOwwzoKJI5NBLy4qiSSCjU+vSsAl5K\n");
        cer.append("Mf4ZCykULL/gU0UDdV7EJv8sNeaE1TJgpKzzGb0l24GqxlvtKqm7XI/D8IQHSCzr\n");
        cer.append("IeLAyGuIWfvSwhhTF5gXSyPzHDNbcWtSc6kNsk0cwUIiyvr40zPacNiGaPk6swQF\n");
        cer.append("m0d4IxnFdp8NUDrsPdUHD/HXHpX1nTPomXPbsyRC7KM/BK50im7Q8Z+Z1XWza2CC\n");
        cer.append("BKy1P1i8xhf1jKEBlyeR4eVXOQlryCoePtP4/2+l9Hfz4nMi0dcJ1M9FkKRvKQHe\n");
        cer.append("WRRbOA==\n");
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
