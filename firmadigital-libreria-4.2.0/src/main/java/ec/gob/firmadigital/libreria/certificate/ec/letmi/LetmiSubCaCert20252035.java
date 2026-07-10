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
 * Certificado intermedio de Letmi, representado como un objeto
 * <code>X509Certificate</code>.
 *
 * @author Letmi
 */
public class LetmiSubCaCert20252035 extends X509Certificate {

    private final X509Certificate certificate;

    public LetmiSubCaCert20252035() {
        super();

        StringBuilder cer = new StringBuilder();
        cer.append("-----BEGIN CERTIFICATE-----\n");
        cer.append("MIIHaDCCBVCgAwIBAgIKMntQy3ubiU3SUzANBgkqhkiG9w0BAQsFADCBozEaMBgG\n");
        cer.append("A1UEAxMRTEVUTUkgUlNBIFJPT1QgQzExLTArBgNVBAsTJENBIFJTQSBST09UIChD\n");
        cer.append("ZXJ0aWZpY2F0aW9uIFNlcnZpY2VzKTEcMBoGA1UEYRMTVkFURUMtMTc5MzIyMTEw\n");
        cer.append("MTAwMTEbMBkGA1UEChMSTEVUTUkgRUNVQURPUiBTLkEuMQ4wDAYDVQQHEwVRVUlU\n");
        cer.append("TzELMAkGA1UEBhMCRUMwHhcNMjUwMTIwMTc0MDMxWhcNMzUwMTE4MTc0MDMwWjCB\n");
        cer.append("oTEZMBcGA1UEAxMQTEVUTUkgUlNBIFNVQiBDMTEsMCoGA1UECxMjQ0EgUlNBIFNV\n");
        cer.append("QiAoQ2VydGlmaWNhdGlvbiBTZXJ2aWNlcykxHDAaBgNVBGETE1ZBVEVDLTE3OTMy\n");
        cer.append("MjExMDEwMDExGzAZBgNVBAoTEkxFVE1JIEVDVUFET1IgUy5BLjEOMAwGA1UEBxMF\n");
        cer.append("UVVJVE8xCzAJBgNVBAYTAkVDMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKC\n");
        cer.append("AgEA1M3DvpwlXfazc5f0ldHj4Z23qewv591qzySCdb8hFyyFDeR91eddH9K6ha5e\n");
        cer.append("SgGtfN/7rgWEpSQuT80Wlj7WUFx16Sb5YLcA+ymyEGtFOSgJPJFs4Vt+cUe6V/+V\n");
        cer.append("qe0O+K3kVcyiHcHrWpPXmhvX9sdBs4MlHJeWE/tJkbdw2mV7giRYWm0h6sMOmfpi\n");
        cer.append("91pF99Fc3hrvRsh6maWv8FXFHxtB7KLQ6xvDPgH1PffGWq23kE4n8TBAgSWuhHpy\n");
        cer.append("bDeCj0WitdeYwak9CvehUvdWo6sewTTqsdtavz44cPGuhAt2kGc6+X3fb6C56iXj\n");
        cer.append("StXLrSyyaF/ej8CKyLy+l+NmrD45oAmuIhDu0fU2ZJGBTelu7eHk//Yes54zeiqv\n");
        cer.append("cer7EgoG2lZgct+kZ2pmy4XTuUKxF+fO33VWzy76odnIACJIA5JuK7kp06zXxMkH\n");
        cer.append("ZKe56TmLIK6bRPZnip7IRUxh5INMwq/4LnAqS4+s0FVjF372ttCN+TxZWdUlxMAF\n");
        cer.append("94AdUTX3maf+VANeAa1lm3Wxmu64cNJbHez9C359u90vPkIrmE1+qdMmN8or4L08\n");
        cer.append("Vlut7nXYcrz71fLEQ5iktMLcVtukzg6w9TzQhDF4KgTFi3nqziAwx2SnR3IwgMDP\n");
        cer.append("vly/Ovoi+dOylhvt9qkDKpOwj+bFcvJE67JPasD7p1q3XiECAwEAAaOCAZwwggGY\n");
        cer.append("MA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUeRTOpaNkXLtcicGQqdU1nPHG\n");
        cer.append("lGAwagYIKwYBBQUHAQEEXjBcMDcGCCsGAQUFBzAChitodHRwczovL2NlcnRzLmxl\n");
        cer.append("dG1pLmFwcC9MRVRNSV9DQV9ST09UMDEuY3J0MCEGCCsGAQUFBzABhhVodHRwOi8v\n");
        cer.append("b2NzcC5sZXRtaS5hcHAwGQYDVR0RBBIwEIEOaW5mb0BsZXRtaS5hcHAwcgYDVR0g\n");
        cer.append("BGswaTBnBgRVHSAAMF8wOwYIKwYBBQUHAgEWL2h0dHBzOi8vbGV0bWkuYXBwL2Rv\n");
        cer.append("Y3VtZW50b3MvTWFyY29fcmVndWxhdG9yaW8vMCAGCCsGAQUFBwICMBQMEmh0dHBz\n");
        cer.append("Oi8vbGV0bWkuYXBwLzA6BgNVHR8EMzAxMC+gLaArhilodHRwczovL2NybC5sZXRt\n");
        cer.append("aS5hcHAvTEVUTUlfQ0FfUk9PVDAxLmNybDAdBgNVHQ4EFgQUkM2RIYc6MUzlEcKs\n");
        cer.append("2KDTsifbKGMwDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3DQEBCwUAA4ICAQBs8vWK\n");
        cer.append("oouKW73vY7QmVJ7sc1xegNG2NU+NRcpcsj1/VoB8DjrnjIe+ZsE4Uy3KyUL8fhmc\n");
        cer.append("KXNwT2P0Awn4HwbOWIRjyy5yeLeoeyVaMUAOl3zEnAf01eVF2fVBYh2lNE6XwIFX\n");
        cer.append("hvd8OW7iPB6PTOKsXALtPxcHUqoZnGSm7rQ+itrERQcHevT6Rct+9fh1X6sxa1ht\n");
        cer.append("DO+TuvAltAJ/0atVgBMTLoLuL1ztWu5wYrViUykEaiFoT5xdwep8jVflruYU1UWD\n");
        cer.append("VgW0MS/AC8trl4SNKwOXl1fPQBF1/W+B70O9izOKCzv8p6M+TXWXayKdtfzesMxY\n");
        cer.append("4dUoqOo6btf66QoPTkb0gE94I0HQN8gPjuXlWDCVu4/QyEG3Q8fVo+b/D6ZQI5gK\n");
        cer.append("Lxmn2bjlfiqhzpTIuCENorQfBQqhH8zBa8x0iLd0Lxl+XW8UDOVpbrsWR6GPPASd\n");
        cer.append("y+BcBkOFG33LABupN5Yr2u9qqJl+lL8BwujcViHLJWHZvuDzYACBKXlA+X8tSqb1\n");
        cer.append("cGtD8EhxW1ZhSzgip4KbvOyq0hjb28epBxylHrGapVLGp3IUY1rPDQkLziLD5MLV\n");
        cer.append("xd8qay+NeC2kT/yk8CNlVvXLvZgjsUz0xyWBKdeqFWCKG1tVgzd7g7cwKn+sLIfa\n");
        cer.append("8S4VvwXVdIv210Ff8ALmr94816OvlKojaTtF3A==\n");
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
