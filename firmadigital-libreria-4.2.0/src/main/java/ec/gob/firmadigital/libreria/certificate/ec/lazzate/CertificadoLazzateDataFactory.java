/*
 * Copyright (C) 2022
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

import static ec.gob.firmadigital.libreria.certificate.ec.lazzate.CertificadoLazzate.*;
import ec.gob.firmadigital.libreria.exceptions.EntidadCertificadoraNoValidaException;
import static ec.gob.firmadigital.libreria.utils.BouncyCastleUtils.certificateHasPolicy;

import java.security.cert.X509Certificate;

/**
 * Permite construir certificados tipo CertificadoLazzate a partir de
 * certificados X509Certificate.
 *
 * @author Henry Carrera <henry@hyrserv.com>
 */
public class CertificadoLazzateDataFactory {

    public static boolean esCertificadoLazzate(X509Certificate certificado) {
        return (certificateHasPolicy(certificado, OID_CERTIFICADO_PERSONA_NATURAL)
                || certificateHasPolicy(certificado, OID_CERTIFICADO_PERSONA_JURIDICA_EMPRESA)
                || certificateHasPolicy(certificado, OID_CERTIFICADO_REPRESENTANTE_LEGAL)
                || certificateHasPolicy(certificado, OID_CERTIFICADO_MIEMBRO_EMPRESA)
                || certificateHasPolicy(certificado, OID_CERTIFICADO_FUNCIONARIO_PUBLICO)
                || certificateHasPolicy(certificado, OID_CERTIFICADO_SSL)
                || certificateHasPolicy(certificado, OID_CERTIFICADO_PERSONA_NATURAL_PROFESIONAL));
    }

    public static CertificadoLazzate construir(X509Certificate certificado) throws EntidadCertificadoraNoValidaException {
        if (certificateHasPolicy(certificado, OID_CERTIFICADO_PERSONA_NATURAL)) {
            return new CertificadoPersonaNaturalLazzate(certificado);
        } else if (certificateHasPolicy(certificado, OID_CERTIFICADO_PERSONA_JURIDICA_EMPRESA)) {
            return new CertificadoPersonaJuridicaLazzate(certificado);
        } else if (certificateHasPolicy(certificado, OID_CERTIFICADO_REPRESENTANTE_LEGAL)) {
            return new CertificadoPersonaJuridicaLazzate(certificado);
        } else if (certificateHasPolicy(certificado, OID_CERTIFICADO_MIEMBRO_EMPRESA)) {
            return new CertificadoPersonaJuridicaLazzate(certificado);
        } else if (certificateHasPolicy(certificado, OID_CERTIFICADO_FUNCIONARIO_PUBLICO)) {
            return new CertificadoPersonaNaturalLazzate(certificado);
        } else if (certificateHasPolicy(certificado, OID_CERTIFICADO_SSL)) {
            return new CertificadoPersonaNaturalLazzate(certificado);
        } else if (certificateHasPolicy(certificado, OID_CERTIFICADO_PERSONA_NATURAL_PROFESIONAL)) {
            return new CertificadoPersonaNaturalLazzate(certificado);
        } else {
            throw new EntidadCertificadoraNoValidaException("Certificado de Lazzate de tipo desconocido!");
        }
    }
}
