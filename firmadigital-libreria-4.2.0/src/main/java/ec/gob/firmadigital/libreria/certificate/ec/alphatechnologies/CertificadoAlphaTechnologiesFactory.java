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

import ec.gob.firmadigital.libreria.certificate.Certificado;
import static ec.gob.firmadigital.libreria.certificate.CertificadoOids.*;

import ec.gob.firmadigital.libreria.exceptions.EntidadCertificadoraNoValidaException;
import static ec.gob.firmadigital.libreria.utils.BouncyCastleUtils.certificateHasPolicy2;

import java.security.cert.X509Certificate;

/**
 * Permite construir certificados tipo
 * {@link CertificadoAlphaTechnologiesFactory} a partir de certificados
 * X509Certificate.
 *
 * @author Alpha Technologies Cia. Ltda.
 */
public class CertificadoAlphaTechnologiesFactory {

    public static boolean esCertificadoDeAlphaTechnologies(X509Certificate certificado) {
        return (certificateHasPolicy2(certificado, Ext.OID_CERTIFICADO_PERSONA_NATURAL_ALPHA_TECHNOLOGIES)
                || certificateHasPolicy2(certificado, Ext.OID_CERTIFICADO_PERSONA_JURIDICA_ALPHA_TECHNOLOGIES)
                || certificateHasPolicy2(certificado, Ext.OID_CERTIFICADO_MIEMBRO_EMPRESA_ALPHA_TECHNOLOGIES)
                || certificateHasPolicy2(certificado, Subj.OID_CERTIFICADO_PERSONA_NATURAL_ALPHA_TECHNOLOGIES)
                || certificateHasPolicy2(certificado, Subj.OID_CERTIFICADO_MIEMBRO_EMPRESA_ALPHA_TECHNOLOGIES)
                || certificateHasPolicy2(certificado, Subj.OID_CERTIFICADO_REPRESENTANTE_LEGAL_ALPHA_TECHNOLOGIES));
    }

    public static Certificado construir(X509Certificate certificado) throws EntidadCertificadoraNoValidaException {
        if (certificateHasPolicy2(certificado, Ext.OID_CERTIFICADO_PERSONA_NATURAL_ALPHA_TECHNOLOGIES)) {
            return new ec.gob.firmadigital.libreria.certificate.ec.alphatechnologies.CertificadoPersonaNaturalAlphaTechnologies(certificado);
        } else if (certificateHasPolicy2(certificado, Ext.OID_CERTIFICADO_PERSONA_JURIDICA_ALPHA_TECHNOLOGIES)) {
            return new ec.gob.firmadigital.libreria.certificate.ec.alphatechnologies.CertificadoPersonaJuridicaAlphaTechnologies(certificado);
        } else if (certificateHasPolicy2(certificado, Ext.OID_CERTIFICADO_MIEMBRO_EMPRESA_ALPHA_TECHNOLOGIES)) {
            return new ec.gob.firmadigital.libreria.certificate.ec.alphatechnologies.CertificadoMiembroEmpresaAlphaTechnologies(certificado);
        } else if (certificateHasPolicy2(certificado, Subj.OID_CERTIFICADO_PERSONA_NATURAL_ALPHA_TECHNOLOGIES)) {
            return new CertificadoPersonaNaturalSubjAlphaTechnologies(certificado);
        } else if (certificateHasPolicy2(certificado, Subj.OID_CERTIFICADO_MIEMBRO_EMPRESA_ALPHA_TECHNOLOGIES)) {
            return new CertificadoMiembroEmpresaSubjAlphaTechnologies(certificado);
        } else if (certificateHasPolicy2(certificado, Subj.OID_CERTIFICADO_REPRESENTANTE_LEGAL_ALPHA_TECHNOLOGIES)) {
            return new CertificadoRepresentanteLegalSubjAlphaTechnologies(certificado);
        } else {
            throw new EntidadCertificadoraNoValidaException("Certificado de Alpha Technologies Cia. Ltda. sin categorizar!");
        }
    }

}
