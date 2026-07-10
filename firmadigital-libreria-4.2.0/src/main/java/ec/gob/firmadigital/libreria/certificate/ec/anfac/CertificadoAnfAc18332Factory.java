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
package ec.gob.firmadigital.libreria.certificate.ec.anfac;

import ec.gob.firmadigital.libreria.exceptions.EntidadCertificadoraNoValidaException;
import static ec.gob.firmadigital.libreria.utils.BouncyCastleUtils.certificateHasPolicy;

import java.security.cert.X509Certificate;

/**
 * Permite construir certificados tipo Certificado ANF AC a partir de
 * certificados X509Certificate.
 *
 * @author Misael Fernández
 */
public class CertificadoAnfAc18332Factory {

    public static boolean esCertificadoDeAnfAc18332(X509Certificate certificado) {
        byte[] valor = certificado.getExtensionValue(CertificadoAnfAc18332.OID_CEDULA_PASAPORTE);
        return (valor != null);
    }

    public static CertificadoAnfAc18332 construir(X509Certificate certificado) throws EntidadCertificadoraNoValidaException {
        if (!esCertificadoDeAnfAc18332(certificado)) {
            throw new IllegalStateException("Este no es un certificado emitido por ANF AC Ecuador");
        }

        if (certificateHasPolicy(certificado, CertificadoAnfAc18332.OID_CERTIFICADO_PERSONA_NATURAL)) {
            return new CertificadoPersonaNaturalAnfAc18332(certificado);
        } else if (certificateHasPolicy(certificado, CertificadoAnfAc18332.OID_CERTIFICADO_PERSONA_JURIDICA)) {
            return new CertificadoPersonaJuridicaAnfAc18332(certificado);
        } else if (certificateHasPolicy(certificado, CertificadoAnfAc18332.OID_CERTIFICADO_FUNCIONARIO_PUBLICO)) {
            return new CertificadoFuncionarioPublicoAnfAc18332(certificado);
        } else {
            throw new EntidadCertificadoraNoValidaException("Certificado ANF AC Ecuador de tipo desconocido!");
        }
    }
}
