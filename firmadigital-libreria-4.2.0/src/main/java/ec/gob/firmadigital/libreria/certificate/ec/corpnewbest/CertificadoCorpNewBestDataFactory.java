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

import static ec.gob.firmadigital.libreria.certificate.ec.corpnewbest.CertificadoCorpNewBest.OID_CEDULA_PASAPORTE;
import static ec.gob.firmadigital.libreria.certificate.ec.corpnewbest.CertificadoCorpNewBest.OID_TIPO_MIEMBRO_EMPRESA;
import static ec.gob.firmadigital.libreria.certificate.ec.corpnewbest.CertificadoCorpNewBest.OID_TIPO_PERSONA_JURIDICA;
import static ec.gob.firmadigital.libreria.certificate.ec.corpnewbest.CertificadoCorpNewBest.OID_TIPO_PERSONA_NATURAL;
import ec.gob.firmadigital.libreria.exceptions.EntidadCertificadoraNoValidaException;
import static ec.gob.firmadigital.libreria.utils.BouncyCastleUtils.certificateHasPolicy;

import java.security.cert.X509Certificate;

/**
 * Permite construir certificados tipo Certificado CorpNewBest a partir de
 * certificados X509Certificate.
 *
 * @author Pedro Reyes
 */
public class CertificadoCorpNewBestDataFactory {

    public static boolean esCertificadoCorpNewBest(X509Certificate certificado) {
        byte[] valor = certificado.getExtensionValue(OID_CEDULA_PASAPORTE);
        return (valor != null);
    }

    public static CertificadoCorpNewBest construir(X509Certificate certificado) throws EntidadCertificadoraNoValidaException {
        if (certificateHasPolicy(certificado, OID_TIPO_PERSONA_NATURAL)) {
            return new CertificadoPersonaNaturalCorpNewBest(certificado);
        } else if (certificateHasPolicy(certificado, OID_TIPO_PERSONA_JURIDICA)) {
            return new CertificadoPersonaJuridicaCorpNewBest(certificado);
        } else if (certificateHasPolicy(certificado, OID_TIPO_MIEMBRO_EMPRESA)) {
            return new CertificadoMiembroEmpresaCorpNewBest(certificado);
        } else {
            throw new EntidadCertificadoraNoValidaException("Tipo Certificado de CorpNewBest desconocido!");
        }
    }
}
