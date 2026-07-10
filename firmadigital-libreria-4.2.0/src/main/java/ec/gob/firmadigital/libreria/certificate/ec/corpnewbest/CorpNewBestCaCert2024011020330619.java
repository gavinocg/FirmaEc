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
 * Certificado raiz de CorpNewBest, representado como un objeto
 * <code>X509Certificate</code>.
 *
 * @author Pedro Reyes
 */
public class CorpNewBestCaCert2024011020330619 extends X509Certificate {

    private X509Certificate certificate;

    public CorpNewBestCaCert2024011020330619() {
        super();

        StringBuilder cer = new StringBuilder();

        cer.append("-----BEGIN CERTIFICATE-----\n");
        cer.append("MIIGXDCCBESgAwIBAgIUZlGg/Exe2zuvgjrm6W43RzkUgfUwDQYJKoZIhvcNAQEN\n");
        cer.append("BQAwgZ0xCzAJBgNVBAYTAkVDMR8wHQYDVQQKDBZDT1JQTkVXQkVTVCBDSUEuIExU\n");
        cer.append("REEuMTAwLgYDVQQLDCdFTlRJREFEIERFIENFUlRJRklDQUNJT04gREUgSU5GT1JN\n");
        cer.append("QUNJT04xOzA5BgNVBAMMMkFVVE9SSURBRCBERSBDRVJUSUZJQ0FDSU9OIFJBSVog\n");
        cer.append("Q0EtMUVGIENPUlBORVdCRVNUMB4XDTI0MDExMDE4MDc1NloXDTMzMDYxOTE4MDc1\n");
        cer.append("NVowgZ0xCzAJBgNVBAYTAkVDMR8wHQYDVQQKDBZDT1JQTkVXQkVTVCBDSUEuIExU\n");
        cer.append("REEuMTAwLgYDVQQLDCdFTlRJREFEIERFIENFUlRJRklDQUNJT04gREUgSU5GT1JN\n");
        cer.append("QUNJT04xOzA5BgNVBAMMMkFVVE9SSURBRCBERSBDRVJUSUZJQ0FDSU9OIFJBSVog\n");
        cer.append("Q0EtMUVGIENPUlBORVdCRVNUMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKC\n");
        cer.append("AgEAqSXVGRcOLpQ4OT6Y6lHCfFsqgO+M1y6r5BAc2jbYX7bwTG9L8NB/1de1Fx0b\n");
        cer.append("xM8L3qw4H8Pg1rzrc5eW6UZW9cUW/go8Z49n6xda8kj0n9DqqkzayJ3bbgnSebjZ\n");
        cer.append("mtcZekILExODe8hM6j4KdpEEuZ+fsQqPjRBvMAeriNw5RNuWVtfTqdry+BpEhoZU\n");
        cer.append("//A0QPw1F2wDzW1lBtSKe9qffTKBRoSHvWtPc7LTOLHLt1WLAwVtQ6Hx18pRzHTV\n");
        cer.append("/YfAKEkLB8+jBi4mC+khmpcfrphXAG8TQMOYeFx4M71J0CIoY9qVOqVSFDvctDdq\n");
        cer.append("L9eJQB4h+Jto6pB2IWdu4oFbv7i6QfArg/zxFpof7rkfbrs/YJX6PM9ISJKEaxIT\n");
        cer.append("6dIZ+Hj+ej3bTMSMHLpu2UjqnQLPAQaZwEK07x8U+p3D6YOPqqPG/MDe8hFxpkCD\n");
        cer.append("2mieuQ1R3WogsW6yZDeEFhY7HBtESzLHd1WGxxOJmRdZdbAK2/pnAR4XEe71hJN6\n");
        cer.append("+HWliI6GeHt56cMxWXKJo76EMFcObdAh7bMa5sERqBazBZdaXIGiF2sE6mSAVx8G\n");
        cer.append("GFBm400XmzODeN2AvyxzOVv7fYiCF18w9J/6RjizZ8M8i0ACfSQuBhn1C1DAXbpM\n");
        cer.append("4GkzCTRbcbhMA/5zxRfdB+jutYZtTFrUFy7AHbM7VdPmOxMCAwEAAaOBkTCBjjAP\n");
        cer.append("BgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFKTgx0zh9QPRuSbtoYoS76R/8NlY\n");
        cer.append("MB0GA1UdDgQWBBSk4MdM4fUD0bkm7aGKEu+kf/DZWDArBgNVHRAEJDAigA8yMDI0\n");
        cer.append("MDExMDE4MDc1NlqBDzIwMzMwNjE5MTgwNzU2WjAOBgNVHQ8BAf8EBAMCAYYwDQYJ\n");
        cer.append("KoZIhvcNAQENBQADggIBAFYOzva5kRwQPLDRCRR8FkdMS/YBjkQVM/OTNcKiO+jb\n");
        cer.append("eY/gH0bPecSl+CD2T+VNz/T367rwcQEZ3H/eq2mO4r8jFtlCew0okb+igQLH2n/o\n");
        cer.append("gsaxdqzA/tUJr46l9V1+/fcBafGy1cQquGsWDhTdJkj4EUiFRiTmsj3sXYB2wXLy\n");
        cer.append("Tg0ecPSkt43h+SMJyf2NS2i1E3bk4Incys1YzW0gP4FtYWVPXJRyR/s2jdnFq0bu\n");
        cer.append("y3DuUjldA2mxTzjNz015Jl9zkicpHNWoTDMmxQ/dKm/DYnlEaNTqWR2Jw0kc5By8\n");
        cer.append("qEOvJ6qlZtEBxxcnP23DILIzo73Pgy3Ka510ZN2Q2SQNkm6Q7NJukbI0tS56HJ0j\n");
        cer.append("/odQ7ksqUgVJ9fSdm6+dVUC6iVvaWFxARSW7sMnxqBsJVKBbVYxizZUpJDQMocoQ\n");
        cer.append("/5mpxZ61kQUQhbT3/mP+9Aspp4AP9AzR7b6P/3oo33aN13TAV7WAVblWzDUTXFJR\n");
        cer.append("mGmjWJVS4OSyUnzUujLp8WEgkXPFOdoiOTkHb3nn/KuElolLX+FdE2R7q0OdKB38\n");
        cer.append("I8i2osAN6RAItDTmZ+Ic4GgUAVW7SVGHDzmNqGi1+0sBZzsJOcXzCJtjQl26ftoP\n");
        cer.append("vzacEKlR5c69J/tR5mMF3uzf2Kt5dN33ZS9vMWDmGSFNlbpMJoXTqMMbPkwQVG0+\n");
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
