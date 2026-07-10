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
public class CorpNewBestCaCert extends X509Certificate {

    private X509Certificate certificate;

    public CorpNewBestCaCert() {
        super();

        StringBuilder cer = new StringBuilder();

        cer.append("-----BEGIN CERTIFICATE-----\n");
        cer.append("MIIGWDCCBECgAwIBAgIUBTK4CcsDoDjTUyPuoWbR9KCHb6QwDQYJKoZIhvcNAQEN\n");
        cer.append("BQAwgZsxOTA3BgNVBAMMMEFVVE9SSURBRCBERSBDRVJUSUZJQ0FDSU9OIFJBSVog\n");
        cer.append("Q0EtMSBDT1JQTkVXQkVTVDEwMC4GA1UECwwnRU5USURBRCBERSBDRVJUSUZJQ0FD\n");
        cer.append("SU9OIERFIElORk9STUFDSU9OMR8wHQYDVQQKDBZDT1JQTkVXQkVTVCBDSUEuIExU\n");
        cer.append("REEuMQswCQYDVQQGEwJFQzAeFw0yMzExMTgxMzM0MTBaFw0zMzA2MTIyMzU5NTla\n");
        cer.append("MIGbMTkwNwYDVQQDDDBBVVRPUklEQUQgREUgQ0VSVElGSUNBQ0lPTiBSQUlaIENB\n");
        cer.append("LTEgQ09SUE5FV0JFU1QxMDAuBgNVBAsMJ0VOVElEQUQgREUgQ0VSVElGSUNBQ0lP\n");
        cer.append("TiBERSBJTkZPUk1BQ0lPTjEfMB0GA1UECgwWQ09SUE5FV0JFU1QgQ0lBLiBMVERB\n");
        cer.append("LjELMAkGA1UEBhMCRUMwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCZ\n");
        cer.append("A0t1w85jpbuu+Okq2sqEScoCb5PwpzgSYBYkUC5l+NfB+lg8/XD0gNfBG5Zp6PIV\n");
        cer.append("DeH8WJq+qku8SfTLM4hfkWoQBCwtGv8vmkBrB+LcdF5dDRVDgk3N5MrwnOHIUmOW\n");
        cer.append("i8hqnxEXjT+FALJTXK1xy1UWvdm8nx8DKPgP/aF2mn+NrijgJnK4FcJvzPl4+0sz\n");
        cer.append("kjvwpom7g7WgxPn3uRK0GWEE7OLEwDTQwyNRQXV1QrCYzgJxPsoHR6Ip5LDGWHO8\n");
        cer.append("RH8ZN5xq+58igX3kBpAfsr4++o565coic4if8Ml6fF984Stl+UkpgqcHGH785Q13\n");
        cer.append("gAGu5lZ5X+PBv0ju9hZXLOOyogYtJHHyD6J92cI/hHpMSXYzWHtjcjL5B67wOg+5\n");
        cer.append("c1E268QEq7wQm5+CaCFHplEZ/LlcL/ftIhcAtjJwTX573JiuuGPf/7Yk0TS/5G72\n");
        cer.append("/SzK0KkjZ6RHk142g0vBO6ETvXqbouIhrqJYg/srYU4z6ObQRZ+SujO5ZImDngnv\n");
        cer.append("P/m82QtKP132bfpcG/qqXnL0CjILfQh9VuoZDELK/uVoqWyCQ4yjojZf8ay1EvE8\n");
        cer.append("/p1ZNPQQ81+feTXLSw7y5l91wCwGazo9kRNMScOUB11A2Iyjci58xHng3NUNhYwi\n");
        cer.append("CXDzTFpQEVQE5m7DZDnqWwDF47/Y0RhzMRAQ4IwK2wIDAQABo4GRMIGOMA8GA1Ud\n");
        cer.append("EwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUe37bqEq1Y5IUiIm/1BJx5vdkha4wHQYD\n");
        cer.append("VR0OBBYEFHt+26hKtWOSFIiJv9QSceb3ZIWuMCsGA1UdEAQkMCKADzIwMjMxMTE4\n");
        cer.append("MTMzNDEwWoEPMjAzMjEyMTQxMzQwMTBaMA4GA1UdDwEB/wQEAwIBhjANBgkqhkiG\n");
        cer.append("9w0BAQ0FAAOCAgEAbbO3YFgirRa9skdV+JkCc+VuFTYFc8y5YzXwbiZ4OV9nzY7p\n");
        cer.append("f+pHAroBiDThHeqgjfjjF0SAL32q+sJbc1SZyJSsz2Bvxi9vdXizKYxnstQPrSfk\n");
        cer.append("AidnLCUM384k5URl8/3M5ur4DuTTeLnEQRNkv6NUN9aCsIbZzhrEW7l1HoPJvrP6\n");
        cer.append("KfZRkJg01bfcPGjF/i5X4WaMi61w/aBm+fhNmFYe2/E5qTd5nbjSLVaqjZeysHtT\n");
        cer.append("KcM/dyKS4hB0A2HD0Q08IFPK243NIsHyiIe81gIy0tLdRP0mHqwN+pMzkk1+J99a\n");
        cer.append("gpOLrXjBKvkYPTaNzBaPCSGqps0Zad/xGN0HzfbUkNndbE8BduZuSAFjUIow7nBK\n");
        cer.append("ouSBqblfzDPUFvXJPAzIgD7qmlh7nP1/ztV55N6YdLTplMNXzYoJ6PoUuPRXacL5\n");
        cer.append("C/syRFVIcARp0DZhd9ltecY2jK6k8AuRu7cXAWejuXvrFxBu4dqK4ny93nThsVhM\n");
        cer.append("uecdxAu7a+4VWcB/pXwz90nxVETdGJ7fLGi4YU3eGy2eJjtUHx5K3dpItmcgpeV0\n");
        cer.append("ru5X1ICwYaxK4/w8Tt08NVeGL5vJMo34LkqkMU4rzpQeW1KMQGlbudVk8zJgFbHF\n");
        cer.append("o428plQvXJgZpWLH/wXA/1tFMGYApzlLCTrnaRZlPTH8oq69L5jFKMmNGk8=\n");
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
