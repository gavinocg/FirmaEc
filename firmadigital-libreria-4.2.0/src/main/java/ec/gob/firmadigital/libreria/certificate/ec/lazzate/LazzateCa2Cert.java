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
 * Certificado raiz de Lazzate, representado como un objeto
 * <code>X509Certificate</code>.
 *
 * @author Henry Carrera <henry@hyrserv.com>
 */
public class LazzateCa2Cert extends X509Certificate {

    private X509Certificate certificate;

    public LazzateCa2Cert() {
        super();

        StringBuilder cer = new StringBuilder();
        cer.append("-----BEGIN CERTIFICATE-----\n");
        cer.append("MIIFFDCCA/ygAwIBAgIUfM+ZZPeqa433G8xeter+WEwh8b8wDQYJKoZIhvcNAQEL\n");
        cer.append("BQAwgYkxCzAJBgNVBAYTAkVDMRIwEAYDVQQIDAlQSUNISU5DSEExDjAMBgNVBAcM\n");
        cer.append("BVFVSVRPMRswGQYDVQQKDBJMYXp6YXRlIENpYS4gTHRkYS4xHjAcBgNVBAsMFUVu\n");
        cer.append("dGUgZGUgQ2VydGlmaWNhY2lvbjEZMBcGA1UEAwwQTGF6emF0ZSBSb290IENBMjAg\n");
        cer.append("Fw0yMzExMjkyMjEzMzRaGA8yMDUzMTEyMTIyMTMzNFowgYkxCzAJBgNVBAYTAkVD\n");
        cer.append("MRIwEAYDVQQIDAlQSUNISU5DSEExDjAMBgNVBAcMBVFVSVRPMRswGQYDVQQKDBJM\n");
        cer.append("YXp6YXRlIENpYS4gTHRkYS4xHjAcBgNVBAsMFUVudGUgZGUgQ2VydGlmaWNhY2lv\n");
        cer.append("bjEZMBcGA1UEAwwQTGF6emF0ZSBSb290IENBMjCCASIwDQYJKoZIhvcNAQEBBQAD\n");
        cer.append("ggEPADCCAQoCggEBANPsnG57spuO8mGSQcl/qb9srQCERlPpqzwEnR4H8URwDPXV\n");
        cer.append("W1lrEsl8GGeFKOkUDxWLBKVRmhRNbpUXadB0dYTj8TEzCWPhMTb66t2v70qB9pFa\n");
        cer.append("7ywsnie0+IU6MrE91nimknPIpk2sbyTt0BW4uHzZYQ0mZvufaBrSatLYuip8qzcy\n");
        cer.append("AjCxZNynhc41v9kceY1p/sN+wkF7huS3VTmXQLeI7+QHWBRNta/Z361Tv2daGqsR\n");
        cer.append("viT+bodP3PSHK49eT4iVRj2W5MEGGejv0oZYtUzVU7DaZX5OC51fnBroL8EuxtBj\n");
        cer.append("6dCMgvNeAqAMqFx2avW808AngWdSZ7EhdF4cO50CAwEAAaOCAW4wggFqMB0GA1Ud\n");
        cer.append("DgQWBBQSyTRfn3cPf1bel04Kk50Tp3BtxzAfBgNVHSMEGDAWgBQSyTRfn3cPf1be\n");
        cer.append("l04Kk50Tp3BtxzAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBAjA0\n");
        cer.append("BgNVHR8ELTArMCmgJ6AlhiNodHRwOi8vZW5leDIueHl6L2NybC9sYXp6YXRlQ0Ex\n");
        cer.append("LmNybDCBzQYDVR0gBIHFMIHCMIG/BgkrBgEEAYPPdgEwgbEwQQYIKwYBBQUHAgEW\n");
        cer.append("NWh0dHBzOi8vZW5leHQuZWMvZGVzY2FyZ2FzL3BvbGl0aWNhcy9jZXJ0aWZpY2Fk\n");
        cer.append("b3MucGRmMGwGCCsGAQUFBwICMGAaXkVsIHByZXNlbnRlIGNlcnRpZmljYWRvIGVz\n");
        cer.append("IGVtaXRpZG8gZW4gYmFzZSBhIGxhcyBwb2zDrXRpY2FzIGRlIHNlZ3VyaWRhZCBk\n");
        cer.append("ZSBMYXp6YXRlIENpYS4gTHRkYS4wDQYJKoZIhvcNAQELBQADggEBADGX3Q7+ptYr\n");
        cer.append("yrHxyp/GbEvfcclRswoQ1JXnV/bDq+0oQhsFBfHQ79N+ulQY87F5u/Qj0Hid+rMg\n");
        cer.append("ABZui1omJe8L6j7Gs5RbJgr64KDAY9/ukAGUhjgZG2qw03rpu7njRl/cF45HKilq\n");
        cer.append("khu1Jt+L0AicukoHoKqpe5+qfDvgAGuvdzbjKDI6HRl/6y/gLgzCl4Zkd0SWuI8P\n");
        cer.append("rLjkicM6J0KafQA1d3gwSEYc3OyT9hzOWD4laLALWUnA9AUQz9tC6ChDaN897Wsu\n");
        cer.append("9yLlXH2pg+aR+R2chedkiEYfwul6o1fqVjwG5Oypd+E8lGH4BCKNCmZFfIXiJGlt\n");
        cer.append("Uoct5bQJQEk=\n");
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
