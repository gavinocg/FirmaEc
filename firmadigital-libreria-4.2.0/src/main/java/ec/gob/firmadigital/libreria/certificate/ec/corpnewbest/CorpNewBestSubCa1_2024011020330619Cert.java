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
public class CorpNewBestSubCa1_2024011020330619Cert extends X509Certificate {

    private X509Certificate certificate;

    public CorpNewBestSubCa1_2024011020330619Cert() {
        super();

        StringBuilder cer = new StringBuilder();

        cer.append("-----BEGIN CERTIFICATE-----\n");
        cer.append("MIIIaDCCBlCgAwIBAgIUSTMhPEFvSEqYje5ynuLNKxGM/tYwDQYJKoZIhvcNAQEN\n");
        cer.append("BQAwgZ0xCzAJBgNVBAYTAkVDMR8wHQYDVQQKDBZDT1JQTkVXQkVTVCBDSUEuIExU\n");
        cer.append("REEuMTAwLgYDVQQLDCdFTlRJREFEIERFIENFUlRJRklDQUNJT04gREUgSU5GT1JN\n");
        cer.append("QUNJT04xOzA5BgNVBAMMMkFVVE9SSURBRCBERSBDRVJUSUZJQ0FDSU9OIFJBSVog\n");
        cer.append("Q0EtMUVGIENPUlBORVdCRVNUMB4XDTI0MDExMDE4MTczNFoXDTMzMDYxOTE4MDc1\n");
        cer.append("NVowgZsxCzAJBgNVBAYTAkVDMR8wHQYDVQQKDBZDT1JQTkVXQkVTVCBDSUEuIExU\n");
        cer.append("REEuMTAwLgYDVQQLDCdFTlRJREFEIERFIENFUlRJRklDQUNJT04gREUgSU5GT1JN\n");
        cer.append("QUNJT04xOTA3BgNVBAMMMEFVVE9SSURBRCBERSBDRVJUSUZJQ0FDSU9OIFNVQkNB\n");
        cer.append("LTFFRiBDT1JQTkVXQkVTVDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB\n");
        cer.append("AME5fO55X70mQI6WJqzE7c08sZfe8qePzzCijLFYeAWJ3MApKHx0Aydb2wqTqmY7\n");
        cer.append("KyyWLEegQmkeLd54jqV7q6eJr2WkFLg/RrEBsZd/T3eGrZA31V5RBuHngK50hVD/\n");
        cer.append("XduvnooF4VGu7BUzrVgHDmjjWkRiTmaljKJRQnLYkKT8voPlywrUhlPh71yuPk74\n");
        cer.append("1NtqHA3CnieC2oD0LCDNzbQ51ZJTdTS9k3XO7yVtXAQ4cBzEg1Y7a7bHI4L2/y8T\n");
        cer.append("G86fJBIu5AxIJPea//2QnfQH/LaPKuIYi5m8N4RX0P35D4lH6yK+0ybNkuKUrItl\n");
        cer.append("stX9y33M2IB+ZrX2IvevqnyMMtreXP7qsCGeQ9OrCMaY6oM8/t/WS/1HJj0LIZsK\n");
        cer.append("Z9FzYXqo5YRLBhoz9ciKFkM1jFhrVZU3BhwUKzMAmeTzWGuAS827Lr7L40edCr3E\n");
        cer.append("ukv8HeWXbOkSm2ukne4CRHa2ZE+ElhH4vha+kErzuodZgT8X0xYMzmUx7smhiryI\n");
        cer.append("1lqu+hEJUFjlY4Y23Amk6lEeZewf9I3NZ65WVc6lOgAhO0JUIP5PIUjMTGIDPn6A\n");
        cer.append("swd3N9vSoLa2MZy592hddJWRuOSkjDbRY/75jIO5Pp+plSf9j13iBbVxJOj56xj9\n");
        cer.append("YodICzCRq/j3XEiUs3J308bsYfufvH0d0hKdvKDAGq9ZAgMBAAGjggKeMIICmjAP\n");
        cer.append("BgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFKTgx0zh9QPRuSbtoYoS76R/8NlY\n");
        cer.append("MG0GA1UdIARmMGQwYgYKKwYBBAGCjEwBCTBUMFIGCCsGAQUFBwIBFkZodHRwczov\n");
        cer.append("L3d3dy5uZXdiZXN0Lm5ldC9uZXdzaWduYXBpL2Rvd25sb2Fkcy9ub3JtYXRpdmEv\n");
        cer.append("ZGVjbGFyYWNpb24ucGRmMIIBmQYDVR0fBIIBkDCCAYwwggGIoIHhoIHehoHbaHR0\n");
        cer.append("cDovL2VqYmNhZWUubmV3YmVzdC50ZWNoOjgwODAvZWpiY2EvcHVibGljd2ViL3dl\n");
        cer.append("YmRpc3QvY2VydGRpc3Q/Y21kPWNybCZpc3N1ZXI9Q04lM0RBVVRPUklEQUQrREUr\n");
        cer.append("Q0VSVElGSUNBQ0lPTitTVUJDQS0xRUYrQ09SUE5FV0JFU1QlMkNPVSUzREVOVElE\n");
        cer.append("QUQrREUrQ0VSVElGSUNBQ0lPTitERStJTkZPUk1BQ0lPTiUyQ08lM0RDT1JQTkVX\n");
        cer.append("QkVTVCtDSUEuK0xUREEuJTJDQyUzREVDooGhpIGeMIGbMTkwNwYDVQQDDDBBVVRP\n");
        cer.append("UklEQUQgREUgQ0VSVElGSUNBQ0lPTiBTVUJDQS0xRUYgQ09SUE5FV0JFU1QxHzAd\n");
        cer.append("BgNVBAoMFkNPUlBORVdCRVNUIENJQS4gTFREQS4xMDAuBgNVBAsMJ0VOVElEQUQg\n");
        cer.append("REUgQ0VSVElGSUNBQ0lPTiBERSBJTkZPUk1BQ0lPTjELMAkGA1UEBhMCRUMwHQYD\n");
        cer.append("VR0OBBYEFGmVD4U4mVSIWuXJ9hp1c4j/SvSeMCsGA1UdEAQkMCKADzIwMjQwMTEw\n");
        cer.append("MTgxNzM0WoEPMjAzMzA2MTkxODE3MzRaMA4GA1UdDwEB/wQEAwIBhjANBgkqhkiG\n");
        cer.append("9w0BAQ0FAAOCAgEASinBQSulhcBTKHRK6jkLfGd2HbzbEKCU/ExDdD7tQUDjSVip\n");
        cer.append("iiRxdkW/nUFT5vyCKsX8vuN9LMw14ZarYp/Dp2b+xmeOC3hs9qcvTtej43TWjU4K\n");
        cer.append("QfG44yW5MUD9tSmiM6Ceh5Kdm8vFYWOeSm1NKOCFFycKOTKdHYaUQQz/LT+njlT2\n");
        cer.append("uR47N5BV1m/c5SOg3Y3v8rg8WDF89DEv3oDW4EWgRbiTyrtjH967yGNoS69wBT+k\n");
        cer.append("TUdToh68jdniYG6q6bgdbbQrCneYbpyV1A9shQVND1oluwgIHCIC1zx+answ/h11\n");
        cer.append("yTXri/AGNNaiJNMBB6/ZswnegeMBGUMkGGm3Gbh8OuIKDCK1/LwBXYU6CmfmhI3K\n");
        cer.append("Q8NNGn5T69tKgkGIgbSwwj+R+D6b2I8PG+BeiGkZB495A3+LM0e4zApr8k4TOcZ3\n");
        cer.append("qPHoVxVNiYl5rahZPE0NyR2Xvgqk+XYYOdjQtRGw0hfSjHtYwagD7Avdato1Hj2x\n");
        cer.append("oRwk7ODdcLDUoT1jNuy5Megc3Em90bW/xFn9bFSVQKxQppKz+En//6R+lply0UHO\n");
        cer.append("v7EiSXNabQG/E2MR1czkYjhUiHu3e3p/eG7GQg6/kFqSU55scbHx+RSR/AHS0dTp\n");
        cer.append("nYU++TlDXlDmFq6ZG58kO9p4KuInYnkzq6WcJdm7CyxAMAF5gJ1seDUpqpE=\n");
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
