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
public class CorpNewBestSubCa3_2024011020330619Cert extends X509Certificate {

    private X509Certificate certificate;

    public CorpNewBestSubCa3_2024011020330619Cert() {
        super();

        StringBuilder cer = new StringBuilder();

        cer.append("-----BEGIN CERTIFICATE-----\n");
        cer.append("MIIIaDCCBlCgAwIBAgIUGR5hqoGIB+WukwpjkOqMOeF1UygwDQYJKoZIhvcNAQEN\n");
        cer.append("BQAwgZ0xCzAJBgNVBAYTAkVDMR8wHQYDVQQKDBZDT1JQTkVXQkVTVCBDSUEuIExU\n");
        cer.append("REEuMTAwLgYDVQQLDCdFTlRJREFEIERFIENFUlRJRklDQUNJT04gREUgSU5GT1JN\n");
        cer.append("QUNJT04xOzA5BgNVBAMMMkFVVE9SSURBRCBERSBDRVJUSUZJQ0FDSU9OIFJBSVog\n");
        cer.append("Q0EtMUVGIENPUlBORVdCRVNUMB4XDTI0MDExMDE4MjQ1OVoXDTMzMDYxOTE4MDc1\n");
        cer.append("NVowgZsxCzAJBgNVBAYTAkVDMR8wHQYDVQQKDBZDT1JQTkVXQkVTVCBDSUEuIExU\n");
        cer.append("REEuMTAwLgYDVQQLDCdFTlRJREFEIERFIENFUlRJRklDQUNJT04gREUgSU5GT1JN\n");
        cer.append("QUNJT04xOTA3BgNVBAMMMEFVVE9SSURBRCBERSBDRVJUSUZJQ0FDSU9OIFNVQkNB\n");
        cer.append("LTNFRiBDT1JQTkVXQkVTVDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB\n");
        cer.append("ALAQtlThzSaVQum68seLikuAC1kVMbS+kUIIdsrtW1fF/oy5+8gAmMq2n7y5iJW1\n");
        cer.append("XFuHJvjb/o2AwPwnP+AuUFBPOFCUUlcN0sikR9G37uWCBDrZ1sk5vhZ7ZMs8RAni\n");
        cer.append("NGjjQClwbZdrjYLCpUO6z/gJayGCU5Fi72h/EsE4xFXLMvCg7ZwPQAYWCRNQclsQ\n");
        cer.append("pv6drNWDh/TApgGazMo7H/fLhIHkQIiBYkGg9fVrEOFqoUufF6H9XZFYfLurkwnJ\n");
        cer.append("6QAISnjUuarslVoRbnRLrv+qgdY6U0bNi+3rgbNApQzK7epLPji8PmkKodYMiktc\n");
        cer.append("8zJWzeVqs9BEudyO+jmE1DE+9F5eofT/lWDwCz0FqtPDvwxjlywGp+Ht2WMLU0FG\n");
        cer.append("ZN34sGDmpR54rK3358MTlng6wSeDf5Vt7Lkx6qFxpV0rIHmt2N6yV/1b7PNd1KF8\n");
        cer.append("FPlpOqfKTJeEyNTZ38RqVCVzfL/M0lgjnC6y/ea6v+1GhWsEI8uU4kUN6klLxYp9\n");
        cer.append("5Jbm9tzhg6FWzgW5w7w/+jyt8csBs+wuAM+D3BDzrqNhG7xPIj4saqa9jUX+nN4Z\n");
        cer.append("Fdzc5sfS1oRifOGWIkefOZu3nE1HqwxFN4Kqc2iG3i8+bkIuYBbGtLhq2tRmUG5S\n");
        cer.append("fxp1KYoRHQVq7rSEum2gx7iwKwOo1I1cWZFuYnSiw/LJAgMBAAGjggKeMIICmjAP\n");
        cer.append("BgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFKTgx0zh9QPRuSbtoYoS76R/8NlY\n");
        cer.append("MG0GA1UdIARmMGQwYgYKKwYBBAGCjEwBCTBUMFIGCCsGAQUFBwIBFkZodHRwczov\n");
        cer.append("L3d3dy5uZXdiZXN0Lm5ldC9uZXdzaWduYXBpL2Rvd25sb2Fkcy9ub3JtYXRpdmEv\n");
        cer.append("ZGVjbGFyYWNpb24ucGRmMIIBmQYDVR0fBIIBkDCCAYwwggGIoIHhoIHehoHbaHR0\n");
        cer.append("cDovL2VqYmNhZWUubmV3YmVzdC50ZWNoOjgwODAvZWpiY2EvcHVibGljd2ViL3dl\n");
        cer.append("YmRpc3QvY2VydGRpc3Q/Y21kPWNybCZpc3N1ZXI9Q04lM0RBVVRPUklEQUQrREUr\n");
        cer.append("Q0VSVElGSUNBQ0lPTitTVUJDQS0zRUYrQ09SUE5FV0JFU1QlMkNPVSUzREVOVElE\n");
        cer.append("QUQrREUrQ0VSVElGSUNBQ0lPTitERStJTkZPUk1BQ0lPTiUyQ08lM0RDT1JQTkVX\n");
        cer.append("QkVTVCtDSUEuK0xUREEuJTJDQyUzREVDooGhpIGeMIGbMTkwNwYDVQQDDDBBVVRP\n");
        cer.append("UklEQUQgREUgQ0VSVElGSUNBQ0lPTiBTVUJDQS0zRUYgQ09SUE5FV0JFU1QxHzAd\n");
        cer.append("BgNVBAoMFkNPUlBORVdCRVNUIENJQS4gTFREQS4xMDAuBgNVBAsMJ0VOVElEQUQg\n");
        cer.append("REUgQ0VSVElGSUNBQ0lPTiBERSBJTkZPUk1BQ0lPTjELMAkGA1UEBhMCRUMwHQYD\n");
        cer.append("VR0OBBYEFNXJjkizX1GwpZou7vWlHTIDcvXvMCsGA1UdEAQkMCKADzIwMjQwMTEw\n");
        cer.append("MTgyNDU5WoEPMjAzMzA2MTkxODI0NTlaMA4GA1UdDwEB/wQEAwIBhjANBgkqhkiG\n");
        cer.append("9w0BAQ0FAAOCAgEAa5An4g6VkQWKi6/0f/NbnPo3ZXhXidbkEDsnOwUUlkmtFP3G\n");
        cer.append("hvbynMkccdBFytt1DV0cyKPqbmwLE/uumzT53suYJyKtj5f2h/+FHz5yieNm2u9W\n");
        cer.append("3sHJMfytt66sFfUtAAl/GCNN+qZKUSKXU9uyvZ+Xv6CQUuVf0StvOC6M6pdiFrNy\n");
        cer.append("MYK3l9jBNvSSFaos49bLhr9cy2gXC/JhN++Mpapw9zvTkpEMYcnsFTz0Tws+Xn+z\n");
        cer.append("rkqEP0/PgPWQHZQIMT9/PjU6WmaCs+yf3KL+qvPuOXX+96epmOg/BN2arkurVJro\n");
        cer.append("lXgkfnY36gcdwFSWJqUpUBVZTbxhZWJGp4AvEE2IRE4L/yZznXF4oXi6uqWGplSX\n");
        cer.append("2HcJQWdB/0DA/XRdYu1ryRD3JnhXhA2sYUgRpC4z6DE9x5Nz/qYt52xD/7LDp0F9\n");
        cer.append("F0/mbAc+2EGOJVApJkRf5ZfX+oBAo/gKFky6nBRnwnOS9vhnESsG388W3wRwsZTz\n");
        cer.append("5XFCm6hOYUycXH8X2CRYD25Xta1uvHAut7bv5RIbAWn6ARYzBhQ2TMF9LLJG/u17\n");
        cer.append("Cxwk8JB3J8enErYfuuv6nN8Yhw8wpQ+VS7i/vLkIRQrGIKveFhvnDX4mIEGZAla0\n");
        cer.append("llRl7sdOGoUTRNuwTw/4q1mGEDf7jEKoUsVnC19O5co8EOclkuzS/D70iao=\n");
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
