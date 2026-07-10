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
public class CorpNewBestSubCa2_20232033Cert extends X509Certificate {

    private X509Certificate certificate;

    public CorpNewBestSubCa2_20232033Cert() {
        super();

        StringBuilder cer = new StringBuilder();

        cer.append("-----BEGIN CERTIFICATE-----\n");
        cer.append("MIIH6TCCBdGgAwIBAgIUOAsbs9O/Y7ZLB4myFwi1wMUeNLQwDQYJKoZIhvcNAQEN\n");
        cer.append("BQAwgZsxOTA3BgNVBAMMMEFVVE9SSURBRCBERSBDRVJUSUZJQ0FDSU9OIFJBSVog\n");
        cer.append("Q0EtMSBDT1JQTkVXQkVTVDEwMC4GA1UECwwnRU5USURBRCBERSBDRVJUSUZJQ0FD\n");
        cer.append("SU9OIERFIElORk9STUFDSU9OMR8wHQYDVQQKDBZDT1JQTkVXQkVTVCBDSUEuIExU\n");
        cer.append("REEuMQswCQYDVQQGEwJFQzAeFw0yMzExMTgyMDQwMTFaFw0zMzA2MTIyMzU5NTla\n");
        cer.append("MIGZMQswCQYDVQQGEwJFQzEfMB0GA1UECgwWQ09SUE5FV0JFU1QgQ0lBLiBMVERB\n");
        cer.append("LjEwMC4GA1UECwwnRU5USURBRCBERSBDRVJUSUZJQ0FDSU9OIERFIElORk9STUFD\n");
        cer.append("SU9OMTcwNQYDVQQDDC5BVVRPUklEQUQgREUgQ0VSVElGSUNBQ0lPTiBTVUJDQS0y\n");
        cer.append("IENPUlBORVdCRVNUMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAoKrH\n");
        cer.append("Kl5BYOfeg2NxkjOLp5KF+G7ccMBzMuVCpPkDgLjJkpHGKNr6MPvM2aFBzd4Vu9ha\n");
        cer.append("RO0bf6mpRg4v9/nLv2e1Kyn/ZRgB1455sXedFAyst64emLrP/2AzfAtNuMMVvYb7\n");
        cer.append("PzyQI14N5rhEeohDQHjLi9J0imSu+G/1yxVx94hga5+Hv6g7ZNniAWLTwsBOWcvt\n");
        cer.append("cBnWpO1Lhz2jS9/KpG+gL/QWEmj/2O6JGOPWFLQHO9jPSI24JXMqHbsK+pJ1o6pB\n");
        cer.append("sOCQPGEAMmGXpOmj5OhG1e5VaRRFhZ4gCRO+6lKpIDS3BmIJ35oEnA5j0cpnDDNy\n");
        cer.append("FxzBM1vhks8gZydq+gJkodgaplKXaIoT0ob+m5+PUhe6AWAr4bKD9DfCPqNd02mt\n");
        cer.append("3Q3JyjcL6kdS3AMKDquauVjbAOa5WiLQKhV7CvBTWmJR1ulXzyfvApViZT5QH8HH\n");
        cer.append("HCWs9CdCRR3nXvILjVClhQ1+fPuiuSmoqzGEyy8PWMLH/kpjFWGa15H4fHEs6UZ5\n");
        cer.append("unf8CdUj+sQB7M8pDC7dsZZmfiyRL4rbAEkEFPOmyInCLWU9llDum8OSXRml0N1K\n");
        cer.append("piIjopeRtbEJWSZ/lLHlreQ5lL9HocuZM9lUabEqw8G8eWqz09nSZPL61f+D/XxJ\n");
        cer.append("ARog25Jr7fVEPrdGhYbuMh0W+AJ1lFMzAb8TQ3cCAwEAAaOCAiMwggIfMA8GA1Ud\n");
        cer.append("EwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUe37bqEq1Y5IUiIm/1BJx5vdkha4wYwYD\n");
        cer.append("VR0gBFwwWjBYBgorBgEEAYKMTAEJMEowSAYIKwYBBQUHAgEWPGh0dHBzOi8vd3d3\n");
        cer.append("Lm5ld2Jlc3QubmV0L2Rvd25sb2Fkcy9Ob3JtYXRpdmFzL2RlY2xhcmFjaW9uLnBk\n");
        cer.append("ZjCCAVUGA1UdHwSCAUwwggFIMIIBRKCBn6CBnIaBmWh0dHA6Ly9lamJjYS5uZXdi\n");
        cer.append("ZXN0LnRlY2gvZWpiY2EvcHVibGljd2ViL3dlYmRpc3QvY2VydGRpc3Q/Y21kPWNy\n");
        cer.append("bCZpc3N1ZXI9Q049QVVUT1JJREFEIERFIENFUlRJRklDQUNJT04gU1VCQ0EtMiBD\n");
        cer.append("T1JQTkVXQkVTVCxPPUNPUlBORVdCRVNUIENJQS4gTFREQS4sQz1FQ6KBn6SBnDCB\n");
        cer.append("mTE3MDUGA1UEAwwuQVVUT1JJREFEIERFIENFUlRJRklDQUNJT04gU1VCQ0EtMiBD\n");
        cer.append("T1JQTkVXQkVTVDEfMB0GA1UECgwWQ09SUE5FV0JFU1QgQ0lBLiBMVERBLjEwMC4G\n");
        cer.append("A1UECwwnRU5USURBRCBERSBDRVJUSUZJQ0FDSU9OIERFIElORk9STUFDSU9OMQsw\n");
        cer.append("CQYDVQQGEwJFQzAdBgNVHQ4EFgQUWwMa+5JD6hK+2Ucwj+Jfm/+Mu4swDgYDVR0P\n");
        cer.append("AQH/BAQDAgGGMA0GCSqGSIb3DQEBDQUAA4ICAQAhcy4xLAvSbs08WKGYdcY5H76X\n");
        cer.append("z34Ik6VDcFM5FjUwVUOVSTXMETi0jUsC4TeTbbfo6F9DI4VCEmIg7iGHErNEZZXv\n");
        cer.append("PI4v5LaK/DDxt6BMthAxh8L8W8dD3zTMvf6hde0T/gguW0XUayPIKIP0zrd5wV0e\n");
        cer.append("iTz9USYqrWcs2GdtePQ1LkMAWGfk9W7wWCrUafF4biLlOMKB7PxPGtWlaD0GmcO5\n");
        cer.append("XDEKJ6NJOkKFl6h0ddFDhaGi9CeAxrAA/GFofoBLjScVz8PCNiLCiw++3kdjlm6Q\n");
        cer.append("l7k6x0eDeH6eqizTYUIvWA7uHMVWMol02DIp5O7kSFViKHwsJLU4FCB/BLCrx5t9\n");
        cer.append("IZ3/3FEwD0rZaThuHZNM4JmjiSoDZA4KtllFkPtY1hCjasDH8q/Wc3OiYMw2XMAy\n");
        cer.append("Dx4P8bIE6zwHSrfzsehOaaqdU/zlqEPNUhhtq2YNh9RtbeQe8HKmVvHZdZepLjHh\n");
        cer.append("fWiSSDApD8LKyAwPKJr1MUeUHyC3vNAF5Gq6vRaZVqhy1hz+ax6hTmKXGSAyZnkq\n");
        cer.append("fxJ2uxswZ2FzXfYyFc5Y9XOnaXqYZ7SYtX7drU0AsC4JUW+X27DZjWCGI1mEWaCO\n");
        cer.append("Yo9VaeZG/nuRuLSYqgjYjkPTVnT7MaPQiJt+gDDa/j+URsRU9PowyaF5AFIdhpVg\n");
        cer.append("CIxItg0K17dpX3fFJA==\n");
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
