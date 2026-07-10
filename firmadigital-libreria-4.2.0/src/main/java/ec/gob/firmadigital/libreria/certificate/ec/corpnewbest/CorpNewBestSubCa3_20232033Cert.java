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
public class CorpNewBestSubCa3_20232033Cert extends X509Certificate {

    private X509Certificate certificate;

    public CorpNewBestSubCa3_20232033Cert() {
        super();

        StringBuilder cer = new StringBuilder();

        cer.append("-----BEGIN CERTIFICATE-----\n");
        cer.append("MIIH6TCCBdGgAwIBAgIUYthDcA8Wpo55PgdLCd/+iPH2uzAwDQYJKoZIhvcNAQEN\n");
        cer.append("BQAwgZsxOTA3BgNVBAMMMEFVVE9SSURBRCBERSBDRVJUSUZJQ0FDSU9OIFJBSVog\n");
        cer.append("Q0EtMSBDT1JQTkVXQkVTVDEwMC4GA1UECwwnRU5USURBRCBERSBDRVJUSUZJQ0FD\n");
        cer.append("SU9OIERFIElORk9STUFDSU9OMR8wHQYDVQQKDBZDT1JQTkVXQkVTVCBDSUEuIExU\n");
        cer.append("REEuMQswCQYDVQQGEwJFQzAeFw0yMzExMTgyMDQ3NDVaFw0zMzA2MTIyMzU5NTla\n");
        cer.append("MIGZMQswCQYDVQQGEwJFQzEfMB0GA1UECgwWQ09SUE5FV0JFU1QgQ0lBLiBMVERB\n");
        cer.append("LjEwMC4GA1UECwwnRU5USURBRCBERSBDRVJUSUZJQ0FDSU9OIERFIElORk9STUFD\n");
        cer.append("SU9OMTcwNQYDVQQDDC5BVVRPUklEQUQgREUgQ0VSVElGSUNBQ0lPTiBTVUJDQS0z\n");
        cer.append("IENPUlBORVdCRVNUMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtUdZ\n");
        cer.append("ZO6qmcqzCx9wdP79/D26U/gy8Wq4pANqnNhgX27jd3vm1aLQOt9JI8sASNCxK1bG\n");
        cer.append("T7Xr20JFhuEFKBuWdsHoKAStRRxgUq6GwXfO9tl7VD6af7Z3ctZSydJQY3fR4lRJ\n");
        cer.append("hVfhWrr0xGG5c3yfncm1dfSWTMwHiZ91PtNu3OvtwtINkTLaeJvQWjyS9QgvuFjJ\n");
        cer.append("3l7dfVn9LzxptqA8VMc88rBuyUg2t0LhU7ZCb8iFqz7bjzqMRbDy1/tIzlIHhsJV\n");
        cer.append("ywZ1ahNFbDL9/yH5GKOULEC+ljcQiKTy2TH6FIqIyc9UAHQ+/WUjDlse+WUOfLFv\n");
        cer.append("djXO8LthEavP4ukKxe557Pn/l7LbT393pDH3TLBxU9r0jMtz9Ilg2bYz5gLnovHd\n");
        cer.append("vyXxWc8abM/dDsa8ZLKmqYNVhnWdpJL/zws1g3ZaP5/5ERp6QqPS4BeCD2gSGjlE\n");
        cer.append("dTRpGIWf/+D7fvVP8BnbkpnnHhywBq8yJQ5dH9fe5Mto6YzL4V2H+RX4pLtR9SYP\n");
        cer.append("IpVxLR3T4Iqhh11CB//GtR4ShrVGQxnjMlQ1qf5LRFxDSoGBzov5rE60M/6BK8CT\n");
        cer.append("Z1sCrqfF95DkCPSEQAa13d1mxI1P+E3YsL48J5XtcnAugvNv3PTJ3udcbgMYaENZ\n");
        cer.append("z6E6Jy2A+HfArq7hZYD4sCil4jvBWaa6+tYWvNMCAwEAAaOCAiMwggIfMA8GA1Ud\n");
        cer.append("EwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUe37bqEq1Y5IUiIm/1BJx5vdkha4wYwYD\n");
        cer.append("VR0gBFwwWjBYBgorBgEEAYKMTAEJMEowSAYIKwYBBQUHAgEWPGh0dHBzOi8vd3d3\n");
        cer.append("Lm5ld2Jlc3QubmV0L2Rvd25sb2Fkcy9Ob3JtYXRpdmFzL2RlY2xhcmFjaW9uLnBk\n");
        cer.append("ZjCCAVUGA1UdHwSCAUwwggFIMIIBRKCBn6CBnIaBmWh0dHA6Ly9lamJjYS5uZXdi\n");
        cer.append("ZXN0LnRlY2gvZWpiY2EvcHVibGljd2ViL3dlYmRpc3QvY2VydGRpc3Q/Y21kPWNy\n");
        cer.append("bCZpc3N1ZXI9Q049QVVUT1JJREFEIERFIENFUlRJRklDQUNJT04gU1VCQ0EtMyBD\n");
        cer.append("T1JQTkVXQkVTVCxPPUNPUlBORVdCRVNUIENJQS4gTFREQS4sQz1FQ6KBn6SBnDCB\n");
        cer.append("mTE3MDUGA1UEAwwuQVVUT1JJREFEIERFIENFUlRJRklDQUNJT04gU1VCQ0EtMyBD\n");
        cer.append("T1JQTkVXQkVTVDEfMB0GA1UECgwWQ09SUE5FV0JFU1QgQ0lBLiBMVERBLjEwMC4G\n");
        cer.append("A1UECwwnRU5USURBRCBERSBDRVJUSUZJQ0FDSU9OIERFIElORk9STUFDSU9OMQsw\n");
        cer.append("CQYDVQQGEwJFQzAdBgNVHQ4EFgQUMBxHjHRW3pqi5exXax7L6ShVQH0wDgYDVR0P\n");
        cer.append("AQH/BAQDAgGGMA0GCSqGSIb3DQEBDQUAA4ICAQBWF/C8MtXLU/sn1APLpphr6Ken\n");
        cer.append("hEzSVtt4ongl43QpRAz4HsvrEFYdix2OtxSCxHj5RZghRZZon2hKOavz8vqHu5mP\n");
        cer.append("xF/fofbqPmxFGL3n4y3/+QftH7Mzslz/4jt0PI9NS8dHWF42aCTzK/aXSoY5wM1d\n");
        cer.append("AAvg9MDJp8YC/40QwkWQhjGvrdLw0oeOVhPpK6Sgle4Ez9VwKk6U8ksjHwPyNgqN\n");
        cer.append("IvPbliwqTV0iO/XJHoho28urvYRpKb3bRaXsS2DcVUxHYcF0itznbvOXkpZTgl3p\n");
        cer.append("HRLBK3Yz3T2QSFOlMY9Eaa9F13dbUwaVN8c19v8nrIbwLBHDf2zBE5RWj+fiEe7g\n");
        cer.append("bNCrWtJ8uTibY+8voyusjWScRUQ6m5fp4R/WVAB6tHnZYxpitX0D2idXCwPV5FL+\n");
        cer.append("d7R8059XywdSlfb1tlH2epuKzYlv568zzAuXavNWzxq5o4vvSu8mdA1tZmJawCI8\n");
        cer.append("VxlgxPe5WuZ3VNUdAKBnqOTvwmXb9w4TyCQ+6HBhiktbFU3AyiTloawYdXZu7E7o\n");
        cer.append("4ve39pnCgd1BOHl0QpEiRH0wcOVdF1qsZl/sIm1ZCEO8gH7sM0js755rkBTvtmCe\n");
        cer.append("S4c6ut4ylTWJODjEtUfgN6JXiqyhKrVac1NNmoNIwjqR4SDb0oaDvWHGXb0OSSby\n");
        cer.append("OwxYm+IKAVyOy0BZkg==\n");
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
