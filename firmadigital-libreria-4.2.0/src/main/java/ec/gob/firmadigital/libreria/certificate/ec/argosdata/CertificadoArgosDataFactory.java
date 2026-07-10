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
package ec.gob.firmadigital.libreria.certificate.ec.argosdata;

import static ec.gob.firmadigital.libreria.certificate.ec.argosdata.CertificadoArgosData.OID_CEDULA_PASAPORTE;
import static ec.gob.firmadigital.libreria.certificate.ec.argosdata.CertificadoArgosData.OID_TIPO_PERSONA_NATURAL;
import static ec.gob.firmadigital.libreria.certificate.ec.argosdata.CertificadoArgosData.OID_TIPO_REPRESENTANTE_LEGAL;
import ec.gob.firmadigital.libreria.exceptions.EntidadCertificadoraNoValidaException;
import static ec.gob.firmadigital.libreria.utils.BouncyCastleUtils.certificateHasPolicy;

import java.security.cert.X509Certificate;

/**
 * Permite construir certificados tipo CertificadoArgosData a partir de
 * certificados X509Certificate.
 *
 * @author Ricardo Arguello
 */
public class CertificadoArgosDataFactory {

    public static boolean esCertificadoArgosData(X509Certificate certificado) {
        byte[] valor = certificado.getExtensionValue(OID_CEDULA_PASAPORTE);
        return (valor != null);
    }

    public static CertificadoArgosData construir(X509Certificate certificado) throws EntidadCertificadoraNoValidaException {
        if (certificateHasPolicy(certificado, OID_TIPO_PERSONA_NATURAL)) {
            return new CertificadoPersonaNaturalArgosData(certificado);
        } else if (certificateHasPolicy(certificado, OID_TIPO_REPRESENTANTE_LEGAL)) {
            return new CertificadoRepresentanteLegalArgosData(certificado);
        } else {
            throw new EntidadCertificadoraNoValidaException("Tipo Certificado de ArgosData desconocido!");
        }
    }
}
