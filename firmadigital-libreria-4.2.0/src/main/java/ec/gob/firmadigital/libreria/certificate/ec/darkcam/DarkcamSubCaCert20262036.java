/*
 * Copyright (C) 2026
 * Authors: Misael Fernández, DARKCAM S.A.
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
package ec.gob.firmadigital.libreria.certificate.ec.darkcam;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.util.Date;
import java.util.Set;

/**
 * Certificado subordinado de DARKCAM S.A. (SubCA), representado como un objeto
 * <code>X509Certificate</code>.
 *
 * @author DARKCAM S.A.
 */
public class DarkcamSubCaCert20262036 extends X509Certificate {

    private final X509Certificate certificate;

    public DarkcamSubCaCert20262036() {
        super();

        StringBuilder cer = new StringBuilder();
        cer.append("-----BEGIN CERTIFICATE-----\n");
        cer.append("MIIHgzCCBWugAwIBAgIQMw4lJdaftAbopJp3WBIL4TANBgkqhkiG9w0BAQsFADBo\n");
        cer.append("MQswCQYDVQQGEwJFQzEVMBMGA1UECgwMREFSS0NBTSBTLkEuMQwwCgYDVQQLDANQ\n");
        cer.append("S0kxEjAQBgNVBAgMCVBpY2hpbmNoYTEQMA4GA1UEAwwHQ0EgUm9vdDEOMAwGA1UE\n");
        cer.append("BwwFUXVpdG8wHhcNMjYwMTI5MjM0MDEyWhcNMzYwMTMwMDA0MDEyWjCBlTELMAkG\n");
        cer.append("A1UEBhMCRUMxFTATBgNVBAoMDERBUktDQU0gUy5BLjEjMCEGA1UECwwaQ0EgRW1p\n");
        cer.append("c29yYSBkZSBDZXJ0aWZpY2Fkb3MxEjAQBgNVBAgMCVBpY2hpbmNoYTEmMCQGA1UE\n");
        cer.append("AwwdREFSS0NBTSBTLkEuIC0gQ0EgU3Vib3JkaW5hZGExDjAMBgNVBAcMBVF1aXRv\n");
        cer.append("MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAyu3gDoFyOXcZAqqG+kFW\n");
        cer.append("PC3boiD7wCqu7C8TD7Cnm5dXL19snmVPSZBXbTtQxRu33AP/uqvMadfJIisJPl7f\n");
        cer.append("i2GVxb7wN/GAwlzrVWwqqTPnEHH2KPPNCZT8m3aTFrpPOQzFji706LKp8fB19ls+\n");
        cer.append("0gp5AT7N0vEM3S++tfAlEvrpX5gffON2NKX6+iTl4mtm04MpR4ymhh8DQij+DBCb\n");
        cer.append("ayweRwnxfCbgy/bCmTfY+man/DtiYMB/0DN2GI1xdD1xPCeVcUWWjznRxQvw9XWp\n");
        cer.append("yKzVlHmMe1LWdKaThfmkbPwpMIGoTl6KyTk5bYAsiYB2EJksedvDBSrt8vJl7c4B\n");
        cer.append("BJuO5BA5JTMIpFIqypWecZWricYeGqv9UZaiyZ070abjqaHoz077wK7nzyOGEas0\n");
        cer.append("PKzncVDJ8fRsOgbf5ROzMcY3eIcxOBn1aIwhc/dsE/GYPXEVyQy0ngnAeFR47VfW\n");
        cer.append("NKH6bD+pIlgtbLURb5F0IODk7mgsJioSuG3blsV36h7bDNzkAIiNG7q/aCJVLLVg\n");
        cer.append("umBVCY0wr8822A+mgbkDRpCqp+6W+U+TeCAZ/g4gAxKJSpcTTsKEJY1UBYbVK20t\n");
        cer.append("8JJ9mpCPnHKCx1QpTbo+OiO/fVGW6fXAVL3IVoBn+e8/R3Z9U1sBaXhSHORq9eZL\n");
        cer.append("Y4No9axfLWj4LAgtkE0RwpsCAwEAAaOCAfkwggH1MBIGA1UdEwEB/wQIMAYBAf8C\n");
        cer.append("AQAwHwYDVR0jBBgwFoAUEITdEARQk2opfMtgU5MPWTXTt8swHQYDVR0OBBYEFGTG\n");
        cer.append("uh7TqKynb/eYnXZE9qLrGnIRMA4GA1UdDwEB/wQEAwIBhjAmBgNVHREEHzAdgRth\n");
        cer.append("ZG1pbmlzdHJhdGl2b0BkYXJrLWNhbS5jb20wgYIGA1UdHwR7MHkwd6B1oHOGcWh0\n");
        cer.append("dHA6Ly9jYS1yb290LWNybC1kYXJrY2FtLXYyLnMzLnVzLWVhc3QtMS5hbWF6b25h\n");
        cer.append("d3MuY29tL2NybC9jYzg1ZGI1YS03ZTI0LTQzYWQtYTg3My00YzViMDIxMGE3NTMv\n");
        cer.append("RUdTcGZpSGtqbWQuY3JsMEcGCCsGAQUFBwEBBDswOTA3BggrBgEFBQcwAYYraHR0\n");
        cer.append("cDovL29jc3AuYWNtLXBjYS51cy1lYXN0LTEuYW1hem9uYXdzLmNvbTCBmAYDVR0g\n");
        cer.append("BIGQMIGNMIGKBgRVHSAAMIGBMDMGCCsGAQUFBwIBFidodHRwczovL3VuaXZlcnNl\n");
        cer.append("LWlkLmNvbS9kYXJrY2FtL2Nwcy5wZGYwSgYIKwYBBQUHAgIwPgw8Q2VydGlmaWNh\n");
        cer.append("ZG8gZW1pdGlkbyBjb25mb3JtZSBhIGxhcyBwb2xpdGljYXMgZGUgREFSS0NBTSBT\n");
        cer.append("LkEuMA0GCSqGSIb3DQEBCwUAA4ICAQB/tKw4SqGhsCPmLqg6xQa1N9sFowdzCZQS\n");
        cer.append("IjPdBzRxV8TWJmCpAcid+mftd6NoYdT9vI0lvP8Gb4xAbbfuhZYC5jo6ni/1jfX5\n");
        cer.append("4mjDy+ThhScw4LnRkD3Zz8mtIm5L2U8xdwpbIDn7SkoR/O0V6NWZ9Z+joNJ1V9+p\n");
        cer.append("MwickqyoCupyh1KSGyGkRrleRmUhd1ZzzTW41bXEda/D6JSqaHBeL8R63OS8rugv\n");
        cer.append("090i6xexevlv6p0YFRXxgN1MbfpKuNN85D3fXql//I4kn9doYGm9z+jnYQdEm/jR\n");
        cer.append("QhjKfYxmNwHNNW8PyH2tU10j0G5HSzDfu6tZ56ESbdRNm67SLfNFCtXxdY5FYfZp\n");
        cer.append("lK9B/rTyUO55IpVGWXNVfvNZDczHcB17Ei7Lbh4cxbwFXK/V8uQCesbfCXu+kdyH\n");
        cer.append("OcqWG4UAHzb7CcJ+rnFVFi7DKdpJH+WExUJashui0HKR10O0c9Ue4atok+BVRxPT\n");
        cer.append("e3UKZUQ4v08IAtFOiT51C9y5DLB86ltvmhxc6D8E5NLRJZDvLmXSEcVMJsuNJ7OK\n");
        cer.append("oO8u7Tvxww75NuW1C1HWq+91i4vBb3hvfgA5QPOxDBmxzl+HDVPVF+AJ6FjSaO/Z\n");
        cer.append("0ay0zWTpAjIf0ol47PaPmYAeAj1jyIv6vDRVonRgTa8mZzz3ztoJBFrY2Iqi/AhK\n");
        cer.append("pBGcvIfQCw==\n");
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
