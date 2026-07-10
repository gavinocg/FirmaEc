/*
 * Copyright (C) 2025
 * Authors: Misael Fernández, PrimeCoreLat
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
package ec.gob.firmadigital.libreria.certificate.ec.primecorelat;

import static ec.gob.firmadigital.libreria.utils.BouncyCastleUtils.certificateHasPolicy2;
import java.security.cert.X509Certificate;
import ec.gob.firmadigital.libreria.certificate.CertificadoOids.Subj;
import ec.gob.firmadigital.libreria.exceptions.EntidadCertificadoraNoValidaException;

/**
 * Permite construir certificados tipo {@link CertificadoPrimeCoreLatDataFactory} a
 * partir de certificados X509Certificate.
 *
 * @author Henry Carrera <henry@hyrserv.com>
 */
public class CertificadoPrimeCoreLatDataFactory {

    public static boolean esCertificadoPrimeCoreLat(X509Certificate certificado) {
        return (certificateHasPolicy2(certificado,  Subj.OID_CERTIFICADO_PERSONA_NATURAL_PRIMECORELAT)
                || certificateHasPolicy2(certificado, Subj.OID_CERTIFICADO_MIEMBRO_EMPRESA_PRIMECORELAT)
                || certificateHasPolicy2(certificado, Subj.OID_CERTIFICADO_REPRESENTANTE_LEGAL_PRIMECORELAT)
                || certificateHasPolicy2(certificado, Subj.OID_CERTIFICADO_SELLO_ELECTRONICO_PRIMECORELAT));
    }

    public static CertificadoPrimeCoreLat construir(X509Certificate certificado) throws EntidadCertificadoraNoValidaException {
        if (certificateHasPolicy2(certificado,  Subj.OID_CERTIFICADO_PERSONA_NATURAL_PRIMECORELAT)) {
            return new CertificadoPersonaNaturalPrimeCoreLat(certificado);
        } else if (certificateHasPolicy2(certificado, Subj.OID_CERTIFICADO_MIEMBRO_EMPRESA_PRIMECORELAT)) {
            return new CertificadoMiembroEmpresaPrimeCoreLat(certificado);
        } else if (certificateHasPolicy2(certificado, Subj.OID_CERTIFICADO_REPRESENTANTE_LEGAL_PRIMECORELAT)) {
            return new CertificadoPersonaJuridicaPrimeCoreLat(certificado);
        } else if (certificateHasPolicy2(certificado, Subj.OID_CERTIFICADO_SELLO_ELECTRONICO_PRIMECORELAT)) {
            return new CertificadoSelloElectronicoPrimeCoreLat(certificado);
        }  else {
            throw new EntidadCertificadoraNoValidaException("Certificado de Prime de tipo desconocido!");
        }
    }

}
