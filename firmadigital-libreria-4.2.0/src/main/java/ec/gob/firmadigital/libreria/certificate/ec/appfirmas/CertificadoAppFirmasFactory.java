/*
 * Copyright (C) 2025
 * Authors: AppFirmas
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
package ec.gob.firmadigital.libreria.certificate.ec.appfirmas;

import ec.gob.firmadigital.libreria.certificate.Certificado;
import ec.gob.firmadigital.libreria.certificate.CertificadoOids.Subj;
import ec.gob.firmadigital.libreria.exceptions.EntidadCertificadoraNoValidaException;
import static ec.gob.firmadigital.libreria.utils.BouncyCastleUtils.certificateHasPolicy2;

import java.security.cert.X509Certificate;

/**
 * Permite construir certificados tipo {@link CertificadoAppFirmasFactory} a
 * partir de certificados X509Certificate.
 *
 * @author AppFirmas
 */
public class CertificadoAppFirmasFactory {

    public static boolean esCertificadoDeAppFirmas(X509Certificate certificado) {
        return (certificateHasPolicy2(certificado, Subj.OID_CERTIFICADO_PERSONA_NATURAL_APP_FIRMAS)
                || certificateHasPolicy2(certificado, Subj.OID_CERTIFICADO_MIEMBRO_EMPRESA_APP_FIRMAS)
                || certificateHasPolicy2(certificado, Subj.OID_CERTIFICADO_REPRESENTANTE_LEGAL_APP_FIRMAS));
    }

    public static Certificado construir(X509Certificate certificado) throws EntidadCertificadoraNoValidaException {
        if (certificateHasPolicy2(certificado, Subj.OID_CERTIFICADO_PERSONA_NATURAL_APP_FIRMAS)) {
            return new CertificadoPersonaNaturalSubjAppFirmas(certificado);
        } else if (certificateHasPolicy2(certificado, Subj.OID_CERTIFICADO_MIEMBRO_EMPRESA_APP_FIRMAS)) {
            return new CertificadoSelloElectronicoSubjAppFirmas(certificado);
        } else if (certificateHasPolicy2(certificado, Subj.OID_CERTIFICADO_REPRESENTANTE_LEGAL_APP_FIRMAS)) {
            return new CertificadoRepresentanteLegalSubjAppFirmas(certificado);
        } else {
            throw new EntidadCertificadoraNoValidaException("Certificado de APP_FIRMAS sin categorizar!");
        }
    }
}
