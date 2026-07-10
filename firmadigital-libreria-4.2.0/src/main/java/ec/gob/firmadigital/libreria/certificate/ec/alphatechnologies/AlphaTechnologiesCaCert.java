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
 * Certificado raiz de Alpha Technologies CIA. LTDA, representado como un objeto
 * <code>X509Certificate</code>.
 *
 * @author Alpha Technologies Cia. Ltda.
 */
public class AlphaTechnologiesCaCert extends X509Certificate {

    private final X509Certificate certificate;

    public AlphaTechnologiesCaCert() {
        super();

        StringBuilder cer = new StringBuilder();
        cer.append("-----BEGIN CERTIFICATE-----\n");
        cer.append("MIID1DCCArygAwIBAgIQflktBZ7VkCzqNyt6dm/4bDANBgkqhkiG9w0BAQsFADCB\n");
        cer.append("gzELMAkGA1UEBhMCRUMxEjAQBgNVBAgTCVBpY2hpbmNoYTEOMAwGA1UEBxMFUXVp\n");
        cer.append("dG8xJjAkBgNVBAoTHUFscGhhIFRlY2hub2xvZ2llcyBDaWEuIEx0ZGEuMSgwJgYD\n");
        cer.append("VQQDEx9BbHBoYSBUZWNobm9sb2dpZXMgUm9vdCBDQSAyMDIzMB4XDTIzMDMyMjAz\n");
        cer.append("NTkxMFoXDTMzMDMyMjAwMDAwMFowgYMxCzAJBgNVBAYTAkVDMRIwEAYDVQQIEwlQ\n");
        cer.append("aWNoaW5jaGExDjAMBgNVBAcTBVF1aXRvMSYwJAYDVQQKEx1BbHBoYSBUZWNobm9s\n");
        cer.append("b2dpZXMgQ2lhLiBMdGRhLjEoMCYGA1UEAxMfQWxwaGEgVGVjaG5vbG9naWVzIFJv\n");
        cer.append("b3QgQ0EgMjAyMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMruTcGV\n");
        cer.append("tWwJB+zZe3Mw5EEHBgApZuzIF56f+mOwY8WJTlg50O2NpBxdauHnBsNI1Zpmqzvl\n");
        cer.append("O469j743p55ENSoJ3/flrFKP6K0LQb0ErpVeMK+rI1DKmAfEFEFnLgBD5s3kGLiL\n");
        cer.append("CIcB9YxCnHFYDpOJEuJZFFYtlYDLK4I5QxC2ARArD2syd/lK7aBybbU/H9dSpKqv\n");
        cer.append("mvXio00+toboACyAMCrOmwIepVLY83gdlGbdO7yZyOaHkt43ttV9p6yWG/9asquF\n");
        cer.append("8M6XJF7FXfNbNALCZVFaUFASNoaRaRzfjuOx/WUNzALqmccUA6q6cxXaQw97lTmU\n");
        cer.append("DZjU0zdMVjPYQ5cCAwEAAaNCMEAwDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB/wQF\n");
        cer.append("MAMBAf8wHQYDVR0OBBYEFMlov42cAer8lKdFG8vp9AiHCLz0MA0GCSqGSIb3DQEB\n");
        cer.append("CwUAA4IBAQCay9aEGczL3tuHUFWxoMbtWua9Zorkgi5Feksuq7xibsAxgpftolvA\n");
        cer.append("sBWxWvCMdnaq1lMad2TsdqtrceW0Yr/SlvDByD0+chNzcMr/dnPHUTn7Wpbc3V/S\n");
        cer.append("kAOrA8uHDSQUsfitEpi/qiL6io0IRaDkUMeFeTLwaAkfApKdnrJoZt2YAviSK3Az\n");
        cer.append("a00g8U/a6pceZcmMwnOYC/MnTvSS6R7jlPSCOyQcpr63PoqsI2NekeVjpYLHA9na\n");
        cer.append("55q5DWFhtnCxFWmKfawTepzVBkrUqrAvn5z+pRJKYxyQXvNSiywabuFsgVMZ96zP\n");
        cer.append("G5mGLl1Rv6bTqk1JTY9FLrkJfA3CjAdE\n");
        cer.append("-----END CERTIFICATE-----");

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
