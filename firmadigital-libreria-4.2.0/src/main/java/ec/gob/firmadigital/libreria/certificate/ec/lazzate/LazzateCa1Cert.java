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
public class LazzateCa1Cert extends X509Certificate {

    private X509Certificate certificate;

    public LazzateCa1Cert() {
        super();

        StringBuilder cer = new StringBuilder();
        cer.append("-----BEGIN CERTIFICATE-----\n");
        cer.append("MIIFcTCCBFmgAwIBAgIUHt051usZwqVQEoeeAS4FwTr7T4wwDQYJKoZIhvcNAQEL\n");
        cer.append("BQAwgbcxCzAJBgNVBAYTAkVDMRowGAYDVQQIDBFRdWl0byAtIFBpY2hpbmNoYTEO\n");
        cer.append("MAwGA1UEBwwFUXVpdG8xGzAZBgNVBAoMEkxhenphdGUgQ2lhLiBMdGRhLjEeMBwG\n");
        cer.append("A1UECwwVRW50ZSBkZSBDZXJ0aWZpY2FjaW9uMRkwFwYDVQQDDBBMYXp6YXRlIFJv\n");
        cer.append("b3QgQ0ExMSQwIgYJKoZIhvcNAQkBFhVjZXJ0aWZpY2Fkb3NAZW5leHQuZWMwIBcN\n");
        cer.append("MjMxMTEwMjAxMTEwWhgPMjA1MzExMDIyMDExMTBaMIG3MQswCQYDVQQGEwJFQzEa\n");
        cer.append("MBgGA1UECAwRUXVpdG8gLSBQaWNoaW5jaGExDjAMBgNVBAcMBVF1aXRvMRswGQYD\n");
        cer.append("VQQKDBJMYXp6YXRlIENpYS4gTHRkYS4xHjAcBgNVBAsMFUVudGUgZGUgQ2VydGlm\n");
        cer.append("aWNhY2lvbjEZMBcGA1UEAwwQTGF6emF0ZSBSb290IENBMTEkMCIGCSqGSIb3DQEJ\n");
        cer.append("ARYVY2VydGlmaWNhZG9zQGVuZXh0LmVjMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n");
        cer.append("MIIBCgKCAQEA5LAMYiotndbFw9IMTegql6LlCn3I09w70fff5oRpryX18++c47Ms\n");
        cer.append("PIelsUoTDQ2Av2oXn55p7C9PHyTOnGGBgS3VJuVysiIoD58ozBcdGkg9+N2n8n8U\n");
        cer.append("yNfo5vYviC3/PdTr8MoUKbIBgWQYhQxzT2Ue7WG/cwYUupaZIT+5n6E+gLX1vHJ7\n");
        cer.append("9v0Pw7+B+6E7a+dZikFtD3C9+vitmn2OG6l8mWng0VqKXwNUwF6h9T4meBTjQMoE\n");
        cer.append("oW7G8E4jUpGlzCysqeF/Me/sRRE4hFuw4eOMyFw2AQcFF5VFNPLsjWKU+y6NMQ9e\n");
        cer.append("hzlJrRFwXujPNEFCnO0Bn51L7nFIp8jefwIDAQABo4IBbzCCAWswHQYDVR0OBBYE\n");
        cer.append("FMY7kALOHWD6Mrra9+KTHattMnGzMB8GA1UdIwQYMBaAFMY7kALOHWD6Mrra9+KT\n");
        cer.append("HattMnGzMA4GA1UdDwEB/wQEAwIBhjASBgNVHRMBAf8ECDAGAQH/AgECMDUGA1Ud\n");
        cer.append("HwQuMCwwKqAooCaGJGh0dHA6Ly9lbmV4dDEueHl6L2NybC9sYXp6YXRlQ0ExLmNy\n");
        cer.append("bDCBzQYDVR0gBIHFMIHCMIG/BgkrBgEEAYPPdgEwgbEwQQYIKwYBBQUHAgEWNWh0\n");
        cer.append("dHBzOi8vZW5leHQuZWMvZGVzY2FyZ2FzL3BvbGl0aWNhcy9jZXJ0aWZpY2Fkb3Mu\n");
        cer.append("cGRmMGwGCCsGAQUFBwICMGAaXkVsIHByZXNlbnRlIGNlcnRpZmljYWRvIGVzIGVt\n");
        cer.append("aXRpZG8gZW4gYmFzZSBhIGxhcyBwb2zDrXRpY2FzIGRlIHNlZ3VyaWRhZCBkZSBM\n");
        cer.append("YXp6YXRlIENpYS4gTHRkYS4wDQYJKoZIhvcNAQELBQADggEBAGylLKqr30h/kijt\n");
        cer.append("YBJcTQoL4Ix5r9CmwJ4xIpV41eBDz/CNPzDnEiEhP8kf+2OQHTo/KmwTzA+CMkfP\n");
        cer.append("9bMkh4TdBbUaIh2MhcDYd1gLW6BFuuk+1GOUwu52AIpyiB8gWeoGEN7l/GchhZSg\n");
        cer.append("BBNoPw6Xvxo9h1X9npnBleKZLZ9gCfFRujOSnI5LMpxUmnYyAorNCIycc+zoAOw+\n");
        cer.append("i9xfXaL1gwRq45g5lrNCq1CkG4M4vQOWsGbCBzsd4q9vwK0LvxpGt3gOpB3emSG0\n");
        cer.append("+Tsz7eQegyIXXKqF3Kn0npe2gC9BkkpBJBYQhdP4LnExeXIsdUXMt8xFRU58Uol8\n");
        cer.append("y9DaQ98=\n");
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
