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
public class LazzateSubCa1Cert extends X509Certificate {

    private X509Certificate certificate;

    public LazzateSubCa1Cert() {
        super();

        StringBuilder cer = new StringBuilder();
        cer.append("-----BEGIN CERTIFICATE-----\n");
        cer.append("MIIEpzCCA4+gAwIBAgIUUWAln6vY4VwosF6dy6AZz+XbasAwDQYJKoZIhvcNAQEL\n");
        cer.append("BQAwgbcxCzAJBgNVBAYTAkVDMRowGAYDVQQIDBFRdWl0byAtIFBpY2hpbmNoYTEO\n");
        cer.append("MAwGA1UEBwwFUXVpdG8xGzAZBgNVBAoMEkxhenphdGUgQ2lhLiBMdGRhLjEeMBwG\n");
        cer.append("A1UECwwVRW50ZSBkZSBDZXJ0aWZpY2FjaW9uMRkwFwYDVQQDDBBMYXp6YXRlIFJv\n");
        cer.append("b3QgQ0ExMSQwIgYJKoZIhvcNAQkBFhVjZXJ0aWZpY2Fkb3NAZW5leHQuZWMwHhcN\n");
        cer.append("MjMxMTEwMjAzMTI3WhcNMzMxMTA3MjAzMTI3WjCBgzELMAkGA1UEBhMCRUMxGjAY\n");
        cer.append("BgNVBAgMEVF1aXRvIC0gUGljaGluY2hhMRswGQYDVQQKDBJMYXp6YXRlIENpYS4g\n");
        cer.append("THRkYS4xHjAcBgNVBAsMFUVudGUgZGUgQ2VydGlmaWNhY2lvbjEbMBkGA1UEAwwS\n");
        cer.append("TGF6emF0ZSBFbWlzb3IgQ0ExMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC\n");
        cer.append("AQEAx2sZgdZmUTbUlqTUZPCe2foZ/j63j+YeJamT+FBqgl9YJLpk+Ofwxb0N70ws\n");
        cer.append("LJjrxihG6kdAGddvy13L9VoDEsBodLnd/3FutgzdLXloL3AY4GYj7OKgauWLHbUN\n");
        cer.append("lRrysNZzIQVC9NyxDWIHojvuc+6NjmZGQzsDNd0Pwr/D6gv3X/A2e8Ez3uzRvOLv\n");
        cer.append("7C/nkWjd1UEmnT6Bmzh/eIhU8b8z2yWq20QocNcRiX4xftSgON3V0XbIY/4iFa18\n");
        cer.append("6Rg19/7Yzp2VK9pSX8s5s7mw1/bE6s3rNW7maspwcL/yJtdMnITCLXCpLKSoTGBN\n");
        cer.append("8Q390h+kBpYunarwIl2teWhOfwIDAQABo4HcMIHZMB0GA1UdDgQWBBQTjc4bTPpP\n");
        cer.append("aQvsN7GCuplET0rQoDAfBgNVHSMEGDAWgBTGO5ACzh1g+jK62vfikx2rbTJxszAS\n");
        cer.append("BgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjA1BgNVHR8ELjAsMCqg\n");
        cer.append("KKAmhiRodHRwOi8vZW5leHQxLnh5ei9jcmwvbGF6emF0ZUNBMS5jcmwwPAYIKwYB\n");
        cer.append("BQUHAQEEMDAuMCwGCCsGAQUFBzABhiBodHRwOi8vZW5leHQxLnh5ejo4Nzc3L2Fk\n");
        cer.append("c3Mvb2NzcDANBgkqhkiG9w0BAQsFAAOCAQEAXm6upbz29J4HGzKjGtZJe3wM2WmE\n");
        cer.append("BzQmOZFDc0T9M+dkNtZyQzYrasaa6q4rbY2ZryaqLS/vW6nh7wzh8GnRkiOj6It9\n");
        cer.append("4qNwGYBy+EFk24tRh/1HRW2PyHLB+K1X9OtyBnZ/Glh4XmiSjQfp4uJYbf2pTb1Z\n");
        cer.append("QKb7ZFhavekvM7o8GbkGAn2EjDHGSmUX+eRUNjHgCFLIoBB5YwmSU48CY3Q3Vb1a\n");
        cer.append("W3CP13GxTDWqdgzheb2rTg/WfS3Rlrdy9A3yCzA9ZUHZRtSxhrkRw/pv0zl4mnHw\n");
        cer.append("heELwCXqCHRX7Z9UWfSpouv3XetDz80luLDwty7o1CS0q1FZpMFyCqaTGg==\n");
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
