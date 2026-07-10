/*
 * Copyright (C) 2023
 * Authors: Alpha Technologies Cia. Ltda.
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
package ec.gob.firmadigital.libreria.certificate.ec.alphatechnologies;

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
 * Certificado intermedio de Alpha Technologies CIA. LTDA, representado como un
 * objeto <code>X509Certificate</code>.
 *
 * @author Alpha Technologies Cia. Ltda.
 */
public class AlphaTechnologiesSubCaCert20232026 extends X509Certificate {

    private final X509Certificate certificate;

    public AlphaTechnologiesSubCaCert20232026() {
        super();

        StringBuilder cer = new StringBuilder();
        cer.append("-----BEGIN CERTIFICATE-----\n");
        cer.append("MIIFHTCCBAWgAwIBAgIQflktE2KICwPLE6HJ4SOdejANBgkqhkiG9w0BAQsFADCB\n");
        cer.append("gzELMAkGA1UEBhMCRUMxEjAQBgNVBAgTCVBpY2hpbmNoYTEOMAwGA1UEBxMFUXVp\n");
        cer.append("dG8xJjAkBgNVBAoTHUFscGhhIFRlY2hub2xvZ2llcyBDaWEuIEx0ZGEuMSgwJgYD\n");
        cer.append("VQQDEx9BbHBoYSBUZWNobm9sb2dpZXMgUm9vdCBDQSAyMDIzMB4XDTIzMDMyMjAz\n");
        cer.append("NTkyMVoXDTI2MDMyMjAwMDAwMFowgYwxCzAJBgNVBAYTAkVDMRIwEAYDVQQIEwlQ\n");
        cer.append("aWNoaW5jaGExDjAMBgNVBAcTBVF1aXRvMSYwJAYDVQQKEx1BbHBoYSBUZWNobm9s\n");
        cer.append("b2dpZXMgQ2lhLiBMdGRhLjExMC8GA1UEAxMoQWxwaGEgVGVjaG5vbG9naWVzIEF0\n");
        cer.append("bGFzIFNpZ25pbmcgQ0EgMjAyMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC\n");
        cer.append("ggEBAJZSmQZ7dZobm8K9tYRScVf3wNdunckLo42QJpc3C0n1xKsKt7/JkZQOS7Rx\n");
        cer.append("mm0lejjsxGH5iFoIDhG9C7r9liCEYJKflra3qQ6BhDwus3Ut/1X9hk1kt277RWW8\n");
        cer.append("mUqGBbsK+FaeXrUV+TRg0tENerwWzriRs/IEA7Isg8123bIX4Hvp4j6wgtgkz7yM\n");
        cer.append("hi+j3ftMzGKDTrCBeu8Lnojg3Xi4FGc0848v61mzKP4pUXGXJB6Ul6z9t6TYDnY2\n");
        cer.append("CgQpcjckwFTG8ysxSkQ/CKWLxDlkOfVSAkNHx+pKcL3IVr9Zf/5l+B2bS1vpZm9k\n");
        cer.append("LVuUTZosPhcR1Ghiw3ye0GsHv5sCAwEAAaOCAYAwggF8MA4GA1UdDwEB/wQEAwIB\n");
        cer.append("hjApBgNVHSUEIjAgBggrBgEFBQcDAgYIKwYBBQUHAwQGCisGAQQBgjcKAwwwEgYD\n");
        cer.append("VR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUGdSSz/IjLZCV4NsKt6zZRxyY8Ksw\n");
        cer.append("HwYDVR0jBBgwFoAUyWi/jZwB6vyUp0Uby+n0CIcIvPQwgZ4GCCsGAQUFBwEBBIGR\n");
        cer.append("MIGOMEIGCCsGAQUFBzABhjZodHRwOi8vb2NzcC5nbG9iYWxzaWduLmNvbS9hbHBo\n");
        cer.append("YXRlY2hub2xvZ2llc3Jvb3RjYTIwMjMwSAYIKwYBBQUHMAKGPGh0dHA6Ly9zZWN1\n");
        cer.append("cmUuZ2xvYmFsc2lnbi5jb20vYWxwaGF0ZWNobm9sb2dpZXNyb290Y2EyMDIzLmNy\n");
        cer.append("dDBKBgNVHR8EQzBBMD+gPaA7hjlodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL2Fs\n");
        cer.append("cGhhdGVjaG5vbG9naWVzcm9vdGNhMjAyMy5jcmwwDQYJKoZIhvcNAQELBQADggEB\n");
        cer.append("AB6liV6fu4knyDFTtJ14pXbuRtDTOtMpQwDfuPBsRKOXzwDQNsrDiAkH4C/RB2eu\n");
        cer.append("P1D5ltVqUMsTOHEwOJgz108oGnmrVzXzeqv3qjzzLV7iNIj8fXip8iwaKJ+VYgsj\n");
        cer.append("ilVLFjWdv/mnSO9VSjDRu0VUPNQoXy7tTRPgblBKQdIhvF9wtQk86FQmiPTOBCWr\n");
        cer.append("o097ZOwmQIBjj/RR9AEL2n6u/r8Hig/7GNFdtOD1VYGjK6AhY7JUxbkKKP0hY7LB\n");
        cer.append("xmRX9y21ZAZT7mjKhdUwCleCIn96wbM2kS7UV24ZQ1ouQuzbCzQlb2UwsMPgZ0G1\n");
        cer.append("dzYf847TuM1T07jXUnE7AUM=\n");
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
