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
public class LazzateCaWeGoCert extends X509Certificate {

    private X509Certificate certificate;

    public LazzateCaWeGoCert() {
        super();

        StringBuilder cer = new StringBuilder();
        cer.append("-----BEGIN CERTIFICATE-----\n");
        cer.append("MIIFSDCCBDCgAwIBAgIUGoXEdCP8jrhXeRpqb/xHxe+lHecwDQYJKoZIhvcNAQEL\n");
        cer.append("BQAwgZAxCzAJBgNVBAYTAkVDMRIwEAYDVQQIDAlQSUNISU5DSEExDjAMBgNVBAcM\n");
        cer.append("BVFVSVRPMRswGQYDVQQKDBJMYXp6YXRlIENpYS4gTHRkYS4xFjAUBgNVBAsMDVdF\n");
        cer.append("LUdPIExBWlpBVEUxKDAmBgNVBAMMH1dFLUdPIFRFUkNFUiBWSU5DVUxBRE8gUm9v\n");
        cer.append("dCBDQTEwIBcNMjQwMTIwMDE0MzEzWhgPMjA1NDAxMTIwMTQzMTNaMIGQMQswCQYD\n");
        cer.append("VQQGEwJFQzESMBAGA1UECAwJUElDSElOQ0hBMQ4wDAYDVQQHDAVRVUlUTzEbMBkG\n");
        cer.append("A1UECgwSTGF6emF0ZSBDaWEuIEx0ZGEuMRYwFAYDVQQLDA1XRS1HTyBMQVpaQVRF\n");
        cer.append("MSgwJgYDVQQDDB9XRS1HTyBURVJDRVIgVklOQ1VMQURPIFJvb3QgQ0ExMIIBIjAN\n");
        cer.append("BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuqGJ9GTri8W47ELPXJo0PAdul4x1\n");
        cer.append("HtkfPM0obewzrZ1K9xPhOSWri4Gtc58tcAswGnKFkFsutMVuVLzvitdGoVKficvo\n");
        cer.append("/lf0YQEV+BJh7Jk0Lq42c0feUDiaP/4ogTPm4qFvLli+R2kdcLSLkXdPa2aOHTE7\n");
        cer.append("g3AVEOFatqc+SBlIJRFLZgXy5d2TlWJbnfDX1b8h4902+eT60ai+eUZYlDRbJ4Es\n");
        cer.append("aRce8+92yOk4Uq9dz8Yqs+NeMc2TN25Teq9/MG5vJGsqAYzbj1/bhsAMslol3B0m\n");
        cer.append("0gBbH+uwgbKqiT1yvJWXFj3s/vn9vbUbmw526HaTjzHtQFqIxA2IO5+yIQIDAQAB\n");
        cer.append("o4IBlDCCAZAwHQYDVR0OBBYEFOTmNuaGOsQj3FXc1r2TKXjmpdK8MB8GA1UdIwQY\n");
        cer.append("MBaAFOTmNuaGOsQj3FXc1r2TKXjmpdK8MA4GA1UdDwEB/wQEAwIBhjASBgNVHRMB\n");
        cer.append("Af8ECDAGAQH/AgECMDQGA1UdHwQtMCswKaAnoCWGI2h0dHA6Ly93ZS1nby54eXov\n");
        cer.append("Y3JsL2xhenphdGVDQTEuY3JsMIHzBgNVHSAEgeswgegwgeUGCSsGAQQBg892ATCB\n");
        cer.append("1zBCBggrBgEFBQcCARY2aHR0cHM6Ly93ZS1nby54eXovZGVzY2FyZ2FzL3BvbGl0\n");
        cer.append("aWNhcy9jZXJ0aWZpY2Fkb3MucGRmMIGQBggrBgEFBQcCAjCBgxqBgEVsIHByZXNl\n");
        cer.append("bnRlIGNlcnRpZmljYWRvIGVzIGVtaXRpZG8gZW4gYmFzZSBhIGxhcyBwb2zDrXRp\n");
        cer.append("Y2FzIGRlIHNlZ3VyaWRhZCBkZSBXRS1HTyBURVJDRVIgVklOQ1VMQURPIExBWlpB\n");
        cer.append("VEUgRU5URSBERSBDRVJUSUZJQ0FDSU9OMA0GCSqGSIb3DQEBCwUAA4IBAQChfego\n");
        cer.append("SCn33e/mATsVxyVXpw8o1LV2EPOyWVfsWq9NBhNt1bEfu5W7tf9NQ/ngc3i2qG+N\n");
        cer.append("NeHP/9zwi0UvZj+3JSDTfNBbI3mIQqxE5P4vMyAF03eI5httzmSNsZnvSg5pDOWb\n");
        cer.append("PPfNiNlFfOIkExVJ3G891ToV6AXvtqiJ0tNYL/ApuDXWLPQe7TVwXz+2PMsWsafb\n");
        cer.append("uDZQzzH09aEkP9rGn8WgHxqGDqu4em+jwxyJz4KLJlENXywIMbeHPw3bbS5BTlYD\n");
        cer.append("gW19+P97D/15mC3y4sFOENREvQjpOTtuNLsZPMkUcNTth/WmoThuXUNcA2av00+T\n");
        cer.append("wrtj3moaqJNEP0cM\n");
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
