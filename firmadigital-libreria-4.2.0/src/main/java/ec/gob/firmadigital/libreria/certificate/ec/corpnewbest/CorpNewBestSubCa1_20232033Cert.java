/*
 * Copyright (C) 2023
 * Authors: Pedro Reyes
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
package ec.gob.firmadigital.libreria.certificate.ec.corpnewbest;

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
 * Certificado intermedio del CorpNewBest, representado como un objeto
 * <code>X509Certificate</code>.
 *
 * @author Pedro Reyes
 */
public class CorpNewBestSubCa1_20232033Cert extends X509Certificate {

    private X509Certificate certificate;

    public CorpNewBestSubCa1_20232033Cert() {
        super();

        StringBuilder cer = new StringBuilder();

        cer.append("-----BEGIN CERTIFICATE-----\n");
        cer.append("MIIH6TCCBdGgAwIBAgIUUdv9owGGRFzOHhfNApZtUoUsHHEwDQYJKoZIhvcNAQEN\n");
        cer.append("BQAwgZsxOTA3BgNVBAMMMEFVVE9SSURBRCBERSBDRVJUSUZJQ0FDSU9OIFJBSVog\n");
        cer.append("Q0EtMSBDT1JQTkVXQkVTVDEwMC4GA1UECwwnRU5USURBRCBERSBDRVJUSUZJQ0FD\n");
        cer.append("SU9OIERFIElORk9STUFDSU9OMR8wHQYDVQQKDBZDT1JQTkVXQkVTVCBDSUEuIExU\n");
        cer.append("REEuMQswCQYDVQQGEwJFQzAeFw0yMzExMTgyMDI3MDBaFw0zMzA2MTIyMzU5NTla\n");
        cer.append("MIGZMQswCQYDVQQGEwJFQzEfMB0GA1UECgwWQ09SUE5FV0JFU1QgQ0lBLiBMVERB\n");
        cer.append("LjEwMC4GA1UECwwnRU5USURBRCBERSBDRVJUSUZJQ0FDSU9OIERFIElORk9STUFD\n");
        cer.append("SU9OMTcwNQYDVQQDDC5BVVRPUklEQUQgREUgQ0VSVElGSUNBQ0lPTiBTVUJDQS0x\n");
        cer.append("IENPUlBORVdCRVNUMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA7lIS\n");
        cer.append("A0agBuAgwPhOTdzbo6+3pfvGEiBSCDAPZffsAKaiSFXlX10VzavhkgXRPdo4RAbd\n");
        cer.append("R3CkRdg+/6FL+73yFkbKmMaA3E35aWx3163/HXqj4YWQ8CysUkuQFFCmFwNAh/l1\n");
        cer.append("YvIWDK0/1BcZ39MokFwesr2A6SuY0XRI29tXvk2r5gJTUvBPW6wt/ckSSftiXUnx\n");
        cer.append("NUH0c9dUSXmAVktpoTEjxzVxBgFHnv6B1Qgl5ANx/UvsoAr1ZWI88XtNXrUW1eLz\n");
        cer.append("kfz5l4pAYku3sVbmJaBwWrIR4pDZA/aMYBBIH3GVMAjIURkr2stXm7Ul41NTTN1J\n");
        cer.append("KRS/ZcT7PYPNaHvf/g6eTrGD1OHG/243Ja/yvr3h9Dj7rt9WHqykEPYFaeVFT5/R\n");
        cer.append("vPgMFlFIOFQn0JUyUTNCXdsKKEK4hUkoZUzPKmoWoAS5/2EK0b/C8bjg1+24vj0f\n");
        cer.append("ugQIN+r3zQtpKDxdz4uaMq+zthPvy7R6+X+6ILuMOmacoDaoChVTUi433WJlGqWz\n");
        cer.append("bUAvatLzRDM0fO16sIHo91HAzROoG4yWhYIthVDs8B0+1eczbAp7X/JIk7AybVX4\n");
        cer.append("U1GVGLJ37ehM1UJw1bxhXBa5U/o2lfst+PLCgOLpdwcS77GvOJCtUfbHIIsI7nwW\n");
        cer.append("agxVe9VsQIiaQM3XCeg3ZKVWDQIpBwnyoY/5lxECAwEAAaOCAiMwggIfMA8GA1Ud\n");
        cer.append("EwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUe37bqEq1Y5IUiIm/1BJx5vdkha4wYwYD\n");
        cer.append("VR0gBFwwWjBYBgorBgEEAYKMTAEJMEowSAYIKwYBBQUHAgEWPGh0dHBzOi8vd3d3\n");
        cer.append("Lm5ld2Jlc3QubmV0L2Rvd25sb2Fkcy9Ob3JtYXRpdmFzL2RlY2xhcmFjaW9uLnBk\n");
        cer.append("ZjCCAVUGA1UdHwSCAUwwggFIMIIBRKCBn6CBnIaBmWh0dHA6Ly9lamJjYS5uZXdi\n");
        cer.append("ZXN0LnRlY2gvZWpiY2EvcHVibGljd2ViL3dlYmRpc3QvY2VydGRpc3Q/Y21kPWNy\n");
        cer.append("bCZpc3N1ZXI9Q049QVVUT1JJREFEIERFIENFUlRJRklDQUNJT04gU1VCQ0EtMSBD\n");
        cer.append("T1JQTkVXQkVTVCxPPUNPUlBORVdCRVNUIENJQS4gTFREQS4sQz1FQ6KBn6SBnDCB\n");
        cer.append("mTE3MDUGA1UEAwwuQVVUT1JJREFEIERFIENFUlRJRklDQUNJT04gU1VCQ0EtMSBD\n");
        cer.append("T1JQTkVXQkVTVDEfMB0GA1UECgwWQ09SUE5FV0JFU1QgQ0lBLiBMVERBLjEwMC4G\n");
        cer.append("A1UECwwnRU5USURBRCBERSBDRVJUSUZJQ0FDSU9OIERFIElORk9STUFDSU9OMQsw\n");
        cer.append("CQYDVQQGEwJFQzAdBgNVHQ4EFgQUUZYZcQp+GcIPbAfoOizfLma8SE4wDgYDVR0P\n");
        cer.append("AQH/BAQDAgGGMA0GCSqGSIb3DQEBDQUAA4ICAQCGl6y1ZfJkhwnTg7+VXdrAHpsI\n");
        cer.append("Ys9JMssBb3S3dy466Qua14aZt17T7klpSWgXkRwDgPuLMG6gX33JH5oTuaPUdo+B\n");
        cer.append("iD5ZWNnVHk13EAej9+DjW7zWz0vO9mdOHrXaDBNRMgAtj2Xl2r40fG5+OWmarqfj\n");
        cer.append("21wlG1uS9xCMnBFwFV64w3UfMlFcuM5V19jzMoFSHNjm0wVeQEDeQtAYD3W/94+G\n");
        cer.append("eyl0Fs/jSwjb6e+DjcqX06av5DIG7Hvfr3Fs/mzlDEJiQtho+aWLd3NqkGg8doOl\n");
        cer.append("+zAh+sO11sC5jj5ctPMCdJieMbR5fVFw4emJnX9kpxMPc36RIW66fUTLCZE79uOD\n");
        cer.append("AZNDuZ0UJAW/4tfMqfjs4xM7FU5qz11gYh/iuJryrajtOMDw7o+3gVDDpYyLVQfC\n");
        cer.append("63yhDDXdTZzFHixiTlOlfNIcsQwEKBeEAiaSTEQgv9a7Tzpuvw6OBtGZhAY2FAHw\n");
        cer.append("0T0Oivhiq/dE7Q3O0NYZN85jowmo6m7vwjuftSXl6WzfVv/bAUAm6qQQI7Nt5F5e\n");
        cer.append("MIzP8ATwHgAFCiAiyAAXmRVoRK/XeNylcuBN/mPp4g1d2P3rBPsOFjeq1i7hxMsv\n");
        cer.append("7u0C5b6Nku+Zh1X8XrYqYBtzqpLx7rbJG2W1Bft0sioZyFa7bSiiM0p205ADVA4u\n");
        cer.append("9DYV5csOn+G6Q4u+0g==\n");
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
