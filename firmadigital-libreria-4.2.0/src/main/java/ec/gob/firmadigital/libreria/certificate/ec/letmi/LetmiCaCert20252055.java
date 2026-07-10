/*
 * Copyright (C) 2025
 * Authors: Letmi
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
package ec.gob.firmadigital.libreria.certificate.ec.letmi;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.util.Date;
import java.util.Set;

/**
 * Certificado raiz de Letmi, representado como un objeto
 * <code>X509Certificate</code>.
 *
 * @author Letmi
 */
public class LetmiCaCert20252055 extends X509Certificate {

    private final X509Certificate certificate;

    public LetmiCaCert20252055() {
        super();

        StringBuilder cer = new StringBuilder();
        cer.append("-----BEGIN CERTIFICATE-----\n");
        cer.append("MIIGwjCCBKqgAwIBAgIKCznjDQseGzbJyDANBgkqhkiG9w0BAQsFADCBozEaMBgG\n");
        cer.append("A1UEAxMRTEVUTUkgUlNBIFJPT1QgQzExLTArBgNVBAsTJENBIFJTQSBST09UIChD\n");
        cer.append("ZXJ0aWZpY2F0aW9uIFNlcnZpY2VzKTEcMBoGA1UEYRMTVkFURUMtMTc5MzIyMTEw\n");
        cer.append("MTAwMTEbMBkGA1UEChMSTEVUTUkgRUNVQURPUiBTLkEuMQ4wDAYDVQQHEwVRVUlU\n");
        cer.append("TzELMAkGA1UEBhMCRUMwIBcNMjUwMTIwMTcyNzU1WhgPMjA1NTAxMTMxNzI3NTRa\n");
        cer.append("MIGjMRowGAYDVQQDExFMRVRNSSBSU0EgUk9PVCBDMTEtMCsGA1UECxMkQ0EgUlNB\n");
        cer.append("IFJPT1QgKENlcnRpZmljYXRpb24gU2VydmljZXMpMRwwGgYDVQRhExNWQVRFQy0x\n");
        cer.append("NzkzMjIxMTAxMDAxMRswGQYDVQQKExJMRVRNSSBFQ1VBRE9SIFMuQS4xDjAMBgNV\n");
        cer.append("BAcTBVFVSVRPMQswCQYDVQQGEwJFQzCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCC\n");
        cer.append("AgoCggIBAM83JC93oesAe6gJuncYlFOQ46kjcFBO08q1ZzknhRAWqoZibCx2eMc9\n");
        cer.append("HOm0bldrBRytLxqvjeM1ykIuyDC178hsT4CZDLmxnyF3NFc09rUPqgfoyVy1YnUd\n");
        cer.append("hbm1MhLQDP/VbySroCvd2jbq0R455AyhnJYJIavGa84vXwICcozxvCdKCDVMRpLr\n");
        cer.append("orpAoHzhg0r5qZjRFSihgQ8oXvIe8yy39xaWQLmFLY8oRIrqZdxgVIl3V5Mk7YHQ\n");
        cer.append("4cfbIcznu7JPIPQ9kKJdHg+iXG0rX+hk7qRVXF+KsY1G+5arGV4XDrEuO7lhaTJV\n");
        cer.append("luewhAEEb4ToTIuk7dAXk1CcUrrPzV6vBuXcDZew4hztGpp8JRC60RpWxRFbRmkD\n");
        cer.append("krvUBJyloWWRNFvq32tdVgvtXE0HPP+Bo8koQbMwA5xAk5a+/YX6vhne1LR16Km/\n");
        cer.append("d6C47e0roE0WX9vRBYZtkLjOPqb7hiE80tnjwHhAkR7+1Ig+JN9siLmF0beDZHrd\n");
        cer.append("F/JhpUQW4cAC0ThQ/K/rKxphP+H2t81RwGH3wvrXw8vwDTRzEVHHXXcNv2UI4Jxn\n");
        cer.append("A1hxWSn8shnLjH1Q0eW4XkhRd+Ejzd6aNGvoUCKIJAmphQG9dGi2JgzlmD/lKZ3N\n");
        cer.append("tNgzXZEF+Oz0tU4b2K+XKYzP+6EqL0KtIeFcpSxpCutcEQ7RL60bAgMBAAGjgfMw\n");
        cer.append("gfAwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBR5FM6lo2Rcu1yJwZCp1TWc\n");
        cer.append("8caUYDAZBgNVHREEEjAQgQ5pbmZvQGxldG1pLmFwcDByBgNVHSAEazBpMGcGBFUd\n");
        cer.append("IAAwXzA7BggrBgEFBQcCARYvaHR0cHM6Ly9sZXRtaS5hcHAvZG9jdW1lbnRvcy9N\n");
        cer.append("YXJjb19yZWd1bGF0b3Jpby8wIAYIKwYBBQUHAgIwFAwSaHR0cHM6Ly9sZXRtaS5h\n");
        cer.append("cHAvMB0GA1UdDgQWBBR5FM6lo2Rcu1yJwZCp1TWc8caUYDAOBgNVHQ8BAf8EBAMC\n");
        cer.append("AQYwDQYJKoZIhvcNAQELBQADggIBAHJsCzJDJJOUMrMjnAo6YAjtXFoq6z5muvjL\n");
        cer.append("OuXZBS4ujNtn2tCbHM7zw4dvUre4PDdlRLCLRQuTFAbtUAaxf35sRrscCoUquEBD\n");
        cer.append("W4Tp+eQO0JjpUCWdESxNOVOhSO6z+WllAOCuTVzkWX4XXDWODVvNcRhU8srV+pAV\n");
        cer.append("uXQAVdjle2mRwfgg+vgGF4nvVK4z3JbMTThZctisyk835pw/8XTKDKxgS7TQmOy4\n");
        cer.append("H1GE9jlJkFctvOi0hiPA1PgBf/tWOB0TF2vZRR/2UGht+o4qs3AXfZbc4G2fxGFG\n");
        cer.append("x/2paYeH4Fsge/DVy9juv5tbdpXHI9NADO8BWD/VJLp5+us5ViiM2Yk9IXdgqUUx\n");
        cer.append("uGByYGs8q/9w/mNPv2DuDULpm1kk0yrP417LQSXFB2zoL+f3Gld1MSsMgipQTPKg\n");
        cer.append("nspSgQhZFeU8a4rKzPXK9rAb/agrLc5k5jYqtCXpyKHHfncdBpiNCT0lnW3o4lQv\n");
        cer.append("ZF8WsWAucs+2cbPEQmnFItX5h0rGBNetw69rMJ3e9zggTbHkQTj4mRnHUKj6Hbvr\n");
        cer.append("vyWdugvlFrjXRXkbpDCLG0F2XeYis/dy5tQLmOb2rY3F6p3zZVA7ksseL40FML9p\n");
        cer.append("24gBDc/Hdpi4Z+Ym8iKp1KGRWAP67qacmP/naypaCRA3FUGMgjE4/iPgspTI4zvC\n");
        cer.append("K0U0dSaY\n");
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
