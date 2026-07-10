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

import ec.gob.firmadigital.libreria.certificate.Certificado;
import ec.gob.firmadigital.libreria.certificate.CertificadoOids.Subj;
import ec.gob.firmadigital.libreria.exceptions.EntidadCertificadoraNoValidaException;
import static ec.gob.firmadigital.libreria.utils.BouncyCastleUtils.certificateHasPolicy2;

import java.security.cert.X509Certificate;

/**
 * Permite construir certificados tipo
 * {@link CertificadoLetmiFactory} a partir de certificados
 * X509Certificate.
 *
 * @author Letmi
 */
public class CertificadoLetmiFactory {

    public static boolean esCertificadoDeLetmi(X509Certificate certificado) {
        return (certificateHasPolicy2(certificado, Subj.OID_CERTIFICADO_PERSONA_NATURAL_LETMI)
                || certificateHasPolicy2(certificado, Subj.OID_CERTIFICADO_MIEMBRO_EMPRESA_LETMI)
                || certificateHasPolicy2(certificado, Subj.OID_CERTIFICADO_REPRESENTANTE_LEGAL_LETMI));
    }

    public static Certificado construir(X509Certificate certificado) throws EntidadCertificadoraNoValidaException {
        if (certificateHasPolicy2(certificado, Subj.OID_CERTIFICADO_PERSONA_NATURAL_LETMI)) {
            return new CertificadoPersonaNaturalSubjLetmi(certificado);
        } else if (certificateHasPolicy2(certificado, Subj.OID_CERTIFICADO_MIEMBRO_EMPRESA_LETMI)) {
            return new CertificadoSelloElectronicoSubjLetmi(certificado);
        } else if (certificateHasPolicy2(certificado, Subj.OID_CERTIFICADO_REPRESENTANTE_LEGAL_LETMI)) {
            return new CertificadoRepresentanteLegalSubjLetmi(certificado);
        } else {
            throw new EntidadCertificadoraNoValidaException("Certificado de Letmi sin categorizar!");
        }
    }

}
