/*
 * Copyright (C) 2020 
 * Authors: Ricardo Arguello, Misael Fernández
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
package ec.gob.firmadigital.libreria.utils;

import ec.gob.firmadigital.libreria.certificate.CertEcUtils;
import ec.gob.firmadigital.libreria.certificate.ec.alphatechnologies.AlphaTechnologiesCaCert;
import ec.gob.firmadigital.libreria.certificate.ec.alphatechnologies.AlphaTechnologiesCaCert20242034;
import ec.gob.firmadigital.libreria.certificate.ec.anfac.AnfAc18332CaCert20162036;
import ec.gob.firmadigital.libreria.certificate.ec.anfac.AnfAc37442CaCert20192039;
import ec.gob.firmadigital.libreria.certificate.ec.appfirmas.AppFirmasCaCert20252055;
import ec.gob.firmadigital.libreria.certificate.ec.argosdata.ArgosDataCaCert;
import ec.gob.firmadigital.libreria.certificate.ec.bce.BceCaCert;
import ec.gob.firmadigital.libreria.certificate.ec.cj.ConsejoJudicaturaCaCert;
import ec.gob.firmadigital.libreria.certificate.ec.corpnewbest.CorpNewBestCaCert;
import ec.gob.firmadigital.libreria.certificate.ec.corpnewbest.CorpNewBestCaCert2024011020330619;
import ec.gob.firmadigital.libreria.certificate.ec.darkcam.DarkcamCaCert20262046;
import ec.gob.firmadigital.libreria.certificate.ec.datil.DatilCaCert;
import ec.gob.firmadigital.libreria.certificate.ec.firmasegura.FirmaSeguraCaCert;
import ec.gob.firmadigital.libreria.certificate.ec.firmasegura.FirmaSeguraSubCaCert20232043;
import ec.gob.firmadigital.libreria.certificate.ec.lazzate.LazzateCa1Cert;
import ec.gob.firmadigital.libreria.certificate.ec.lazzate.LazzateCa2Cert;
import ec.gob.firmadigital.libreria.certificate.ec.lazzate.LazzateCaCert;
import ec.gob.firmadigital.libreria.certificate.ec.lazzate.LazzateCaWeGoCert;
import ec.gob.firmadigital.libreria.certificate.ec.letmi.LetmiCaCert20252055;
import ec.gob.firmadigital.libreria.certificate.ec.primecorelat.PrimeCoreLatCa1Cert;
import ec.gob.firmadigital.libreria.certificate.ec.primecorelat.PrimeCoreLatCa2Cert;
import ec.gob.firmadigital.libreria.certificate.ec.securitydata.SecurityDataCaCert;
import ec.gob.firmadigital.libreria.certificate.ec.uanataca.UanatacaCaCert;
import ec.gob.firmadigital.libreria.exceptions.EntidadCertificadoraNoValidaException;
import java.net.SocketTimeoutException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorException.Reason;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import ec.gob.firmadigital.libreria.exceptions.RubricaException;

/**
 * Utilidades para OCSP
 *
 * @author jdc
 */
public class OcspUtils {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static boolean isValidCertificate(X509Certificate certificate) throws RubricaException, EntidadCertificadoraNoValidaException {
        List<X509Certificate> certs = new ArrayList<X509Certificate>();
        certs.add(certificate);
        certs.add(CertEcUtils.getRootCertificate(certificate));

        // init certification path
        CertificateFactory cf;
        try {
            cf = CertificateFactory.getInstance("X509");
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
        CertPath cp;
        try {
            cp = cf.generateCertPath(certs);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }

        // load the root CA certificates
        X509Certificate rootCACert1 = new SecurityDataCaCert();
        X509Certificate rootCACert2 = new BceCaCert();
        X509Certificate rootCACert3 = new ConsejoJudicaturaCaCert();
        X509Certificate rootCACert4 = new AnfAc18332CaCert20162036();
        X509Certificate rootCACert5 = new AnfAc37442CaCert20192039();
        X509Certificate rootCACert6 = new UanatacaCaCert();
        X509Certificate rootCACert7 = new DatilCaCert();
        X509Certificate rootCACert8 = new ArgosDataCaCert();
        X509Certificate rootCACert9 = new LazzateCaCert();
        X509Certificate rootCACert10 = new AlphaTechnologiesCaCert();
        X509Certificate rootCACert11 = new CorpNewBestCaCert();
        X509Certificate rootCACert12 = new CorpNewBestCaCert2024011020330619();
        X509Certificate rootCACert13 = new FirmaSeguraCaCert();
        X509Certificate rootCACert14 = new LazzateCa1Cert();
        X509Certificate rootCACert15 = new LazzateCa2Cert();
        X509Certificate rootCACert16 = new LazzateCaCert();
        X509Certificate rootCACert17 = new LazzateCaWeGoCert();
        X509Certificate rootCACert18 = new AlphaTechnologiesCaCert20242034();
        X509Certificate rootCACert19 = new CorpNewBestCaCert();
        X509Certificate rootCACert20 = new CorpNewBestCaCert2024011020330619();
        X509Certificate rootCACert21 = new FirmaSeguraCaCert();
        X509Certificate rootCACert22 = new FirmaSeguraSubCaCert20232043();
        X509Certificate rootCACert23 = new LetmiCaCert20252055();
        X509Certificate rootCACert24 = new AppFirmasCaCert20252055();
        X509Certificate rootCACert25 = new DarkcamCaCert20262046();
        X509Certificate rootCACert26 = new PrimeCoreLatCa1Cert();
        X509Certificate rootCACert27 = new PrimeCoreLatCa2Cert();

        // init root trusted certs
        TrustAnchor ta1 = new TrustAnchor(rootCACert1, null);
        TrustAnchor ta2 = new TrustAnchor(rootCACert2, null);
        TrustAnchor ta3 = new TrustAnchor(rootCACert3, null);
        TrustAnchor ta4 = new TrustAnchor(rootCACert4, null);
        TrustAnchor ta5 = new TrustAnchor(rootCACert5, null);
        TrustAnchor ta6 = new TrustAnchor(rootCACert6, null);
        TrustAnchor ta7 = new TrustAnchor(rootCACert7, null);
        TrustAnchor ta8 = new TrustAnchor(rootCACert8, null);
        TrustAnchor ta9 = new TrustAnchor(rootCACert9, null);
        TrustAnchor ta10 = new TrustAnchor(rootCACert10, null);
        TrustAnchor ta11 = new TrustAnchor(rootCACert11, null);
        TrustAnchor ta12 = new TrustAnchor(rootCACert12, null);
        TrustAnchor ta13 = new TrustAnchor(rootCACert13, null);
        TrustAnchor ta14 = new TrustAnchor(rootCACert14, null);
        TrustAnchor ta15 = new TrustAnchor(rootCACert15, null);
        TrustAnchor ta16 = new TrustAnchor(rootCACert16, null);
        TrustAnchor ta17 = new TrustAnchor(rootCACert17, null);
        TrustAnchor ta18 = new TrustAnchor(rootCACert18, null);
        TrustAnchor ta19 = new TrustAnchor(rootCACert19, null);
        TrustAnchor ta20 = new TrustAnchor(rootCACert20, null);
        TrustAnchor ta21 = new TrustAnchor(rootCACert21, null);
        TrustAnchor ta22 = new TrustAnchor(rootCACert22, null);
        TrustAnchor ta23 = new TrustAnchor(rootCACert23, null);
        TrustAnchor ta24 = new TrustAnchor(rootCACert24, null);
        TrustAnchor ta25 = new TrustAnchor(rootCACert25, null);
        TrustAnchor ta26 = new TrustAnchor(rootCACert26, null);
        TrustAnchor ta27 = new TrustAnchor(rootCACert27, null);

        Set<TrustAnchor> trustedCertsSet = new HashSet<TrustAnchor>();
        trustedCertsSet.add(ta1);
        trustedCertsSet.add(ta2);
        trustedCertsSet.add(ta3);
        trustedCertsSet.add(ta4);
        trustedCertsSet.add(ta5);
        trustedCertsSet.add(ta6);
        trustedCertsSet.add(ta7);
        trustedCertsSet.add(ta8);
        trustedCertsSet.add(ta9);
        trustedCertsSet.add(ta10);
        trustedCertsSet.add(ta11);
        trustedCertsSet.add(ta12);
        trustedCertsSet.add(ta13);
        trustedCertsSet.add(ta14);
        trustedCertsSet.add(ta15);
        trustedCertsSet.add(ta16);
        trustedCertsSet.add(ta17);
        trustedCertsSet.add(ta18);
        trustedCertsSet.add(ta19);
        trustedCertsSet.add(ta20);
        trustedCertsSet.add(ta21);
        trustedCertsSet.add(ta22);
        trustedCertsSet.add(ta23);
        trustedCertsSet.add(ta24);
        trustedCertsSet.add(ta25);
        trustedCertsSet.add(ta26);
        trustedCertsSet.add(ta27);

        // init PKIX parameters
        PKIXParameters params;
        try {
            params = new PKIXParameters(trustedCertsSet);
        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }

        params.setRevocationEnabled(false);

        // enable OCSP
        // Security.setProperty("ocsp.enable", "true");
        // Activate CRLDP
        // System.setProperty("com.sun.security.enableCRLDP", "true");
        // perform validation
        CertPathValidator validator;
        try {
            validator = CertPathValidator.getInstance("PKIX");
        } catch (NoSuchAlgorithmException e) {
            throw new RubricaException(e);
        }

        try {
            CertPathValidatorResult result = validator.validate(cp, params);
            return true;
        } catch (InvalidAlgorithmParameterException e) {
            throw new RubricaException(e);
        } catch (CertPathValidatorException e) {
            Reason reason = e.getReason();
            int index = e.getIndex();
            System.out.println("reason=" + reason + "; index=" + index);

            Throwable t = e.getCause();

            if (t != null) {
                System.out.println("Cause=" + t.getClass());

                if (t instanceof SocketTimeoutException) {
                    System.out.println("Timeout al ir al OCSP server!");
                    return false;
                }
            }

            return false;
        }
    }
}
