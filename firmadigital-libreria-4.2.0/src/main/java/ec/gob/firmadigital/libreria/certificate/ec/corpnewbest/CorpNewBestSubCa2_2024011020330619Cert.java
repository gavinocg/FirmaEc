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
public class CorpNewBestSubCa2_2024011020330619Cert extends X509Certificate {

    private X509Certificate certificate;

    public CorpNewBestSubCa2_2024011020330619Cert() {
        super();

        StringBuilder cer = new StringBuilder();

        cer.append("-----BEGIN CERTIFICATE-----\n");
        cer.append("MIIIaDCCBlCgAwIBAgIUHBwYgbmlntKu8UmCBw5ZXdWDv6wwDQYJKoZIhvcNAQEN\n");
        cer.append("BQAwgZ0xCzAJBgNVBAYTAkVDMR8wHQYDVQQKDBZDT1JQTkVXQkVTVCBDSUEuIExU\n");
        cer.append("REEuMTAwLgYDVQQLDCdFTlRJREFEIERFIENFUlRJRklDQUNJT04gREUgSU5GT1JN\n");
        cer.append("QUNJT04xOzA5BgNVBAMMMkFVVE9SSURBRCBERSBDRVJUSUZJQ0FDSU9OIFJBSVog\n");
        cer.append("Q0EtMUVGIENPUlBORVdCRVNUMB4XDTI0MDExMDE4MjMxMFoXDTMzMDYxOTE4MDc1\n");
        cer.append("NVowgZsxCzAJBgNVBAYTAkVDMR8wHQYDVQQKDBZDT1JQTkVXQkVTVCBDSUEuIExU\n");
        cer.append("REEuMTAwLgYDVQQLDCdFTlRJREFEIERFIENFUlRJRklDQUNJT04gREUgSU5GT1JN\n");
        cer.append("QUNJT04xOTA3BgNVBAMMMEFVVE9SSURBRCBERSBDRVJUSUZJQ0FDSU9OIFNVQkNB\n");
        cer.append("LTJFRiBDT1JQTkVXQkVTVDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB\n");
        cer.append("AL6xn8zOlXYoO5srcGarvDmDDU5Vh5dCxmNfnLEaVq0hj9QGSP0FlBRu3yv2SaYx\n");
        cer.append("HFuN9Z2iPhopy1Q6K2kNuQ/8XZo+rzDxxJNpaxl9gzatytfKHjW2pgujVNiCJd+0\n");
        cer.append("yd5bsHsPl6zJX0h8aIa6ElacaDTl/QGEG5+0prFtUVucjbp6QqLQzcUsNuYJaLdt\n");
        cer.append("kHxaiETrOZFy+ucU8eI9hGmFsmw+EK+BYd7Juqz43dMOX7QtMYARu5IrS931AWbn\n");
        cer.append("feYNkGqIzujMwOqfLONXJcTBNsQRjBptVS0Ttbf1+LgZvowxCXQ77I6BKGIEVl0V\n");
        cer.append("PxwF/WPrXcPE9Cxg9D0ajUGufTv0r4p9ANDpdfuNelgvcvQfoOV0JxIXcAGKeKfQ\n");
        cer.append("kFbzP0+1iBhsYKcq5YmJEW+RTyUR3sTEOPVJErp7XKECp0yxv5H6YFOp/9zR1cVQ\n");
        cer.append("73/FiGA3053UTtZ28bs0nWBge+SWE62PuLedMCUd2WfoHcbJD2npiF92Iq/TUyzw\n");
        cer.append("dAFTuIaoggW0t5io2TUD3jDXvKzAgbHgtRUXip9qCfWRQwnxw9m3urazDGygzg5w\n");
        cer.append("rNNCFcQuIjvGp0SyhDpZZ6uwWCSlBH7byM+m7otdXfq2DYKwxkj+Fn3ABdNwkq69\n");
        cer.append("RUU7uKajSa7NntmD45n0B3JtACDgzRhV6oJCMo1KZ+qjAgMBAAGjggKeMIICmjAP\n");
        cer.append("BgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFKTgx0zh9QPRuSbtoYoS76R/8NlY\n");
        cer.append("MG0GA1UdIARmMGQwYgYKKwYBBAGCjEwBCTBUMFIGCCsGAQUFBwIBFkZodHRwczov\n");
        cer.append("L3d3dy5uZXdiZXN0Lm5ldC9uZXdzaWduYXBpL2Rvd25sb2Fkcy9ub3JtYXRpdmEv\n");
        cer.append("ZGVjbGFyYWNpb24ucGRmMIIBmQYDVR0fBIIBkDCCAYwwggGIoIHhoIHehoHbaHR0\n");
        cer.append("cDovL2VqYmNhZWUubmV3YmVzdC50ZWNoOjgwODAvZWpiY2EvcHVibGljd2ViL3dl\n");
        cer.append("YmRpc3QvY2VydGRpc3Q/Y21kPWNybCZpc3N1ZXI9Q04lM0RBVVRPUklEQUQrREUr\n");
        cer.append("Q0VSVElGSUNBQ0lPTitTVUJDQS0yRUYrQ09SUE5FV0JFU1QlMkNPVSUzREVOVElE\n");
        cer.append("QUQrREUrQ0VSVElGSUNBQ0lPTitERStJTkZPUk1BQ0lPTiUyQ08lM0RDT1JQTkVX\n");
        cer.append("QkVTVCtDSUEuK0xUREEuJTJDQyUzREVDooGhpIGeMIGbMTkwNwYDVQQDDDBBVVRP\n");
        cer.append("UklEQUQgREUgQ0VSVElGSUNBQ0lPTiBTVUJDQS0yRUYgQ09SUE5FV0JFU1QxHzAd\n");
        cer.append("BgNVBAoMFkNPUlBORVdCRVNUIENJQS4gTFREQS4xMDAuBgNVBAsMJ0VOVElEQUQg\n");
        cer.append("REUgQ0VSVElGSUNBQ0lPTiBERSBJTkZPUk1BQ0lPTjELMAkGA1UEBhMCRUMwHQYD\n");
        cer.append("VR0OBBYEFM+JVyPPTz0ayirwTaLfl9roNcfuMCsGA1UdEAQkMCKADzIwMjQwMTEw\n");
        cer.append("MTgyMzEwWoEPMjAzMzA2MTkxODIzMTBaMA4GA1UdDwEB/wQEAwIBhjANBgkqhkiG\n");
        cer.append("9w0BAQ0FAAOCAgEAeibdn2AvDhX4NRDS7UjwJSV6s4fP33b/+OeTFyGJO0/BHRT/\n");
        cer.append("pOReYJ4FSGr7L3pgoJrM3qrpfUxOjlJ7R9J2IiJ7feAali6+OlIbJi4jrdey63UT\n");
        cer.append("S4D8DbL7pOJovgRIRZCWzvGowi6UfvoWibqh/xKVOppIWsPBH+PDjQ7I/uQViQbh\n");
        cer.append("UFm6z4mB6l7+KX1gfIDLD3Qli7bvtWMHy7xh4kp2ukxo/qUkDWQLvnYzYDmYr2s+\n");
        cer.append("nKOdwXJPW8GrAFKNcAv1/ZHKiqRozjP5jjDb+Idirp+YNxeRAytwAEmoYKSx0+EL\n");
        cer.append("U73IjZ44VfkAcmhfg1vLg/uroV6z73WzkTUe/ESNNKQiPo/l73OLLf17XJf66lnT\n");
        cer.append("uGLle1YM99R7FUqGM9a6nkV1AifFvoWCMdOHx/2T8PlzvX6pb1xvvqEjoToiJkzj\n");
        cer.append("q2Nf+X/PIAarrum04UI9NlNFdbQZQedhFseRU7NqNa4Qgs61nuPiTmkZM4TNEMCL\n");
        cer.append("YgpxTlNpBE2XDvwPZndm37NYJlU8ctrdGwcuk3L5yParly2YY+cDCgfk9++7AZGA\n");
        cer.append("HQZZfrIGpKPX51UzcTP1Dkf6TUu2aKNPB1IjNm9NYD3F/TnbGeoU+MwYqlODywVZ\n");
        cer.append("Hvy8o/2bBiqvdstVmcSqiBgtIDWWEh+hc8vEWRuQnorM63xhE1KjikhZnnU=\n");
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
