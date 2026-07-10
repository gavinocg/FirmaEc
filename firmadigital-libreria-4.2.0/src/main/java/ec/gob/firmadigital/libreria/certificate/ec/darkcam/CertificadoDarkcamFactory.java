/*
 * Copyright (C) 2025
 * Authors: Misael Fernández, DARKCAM S.A.
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
package ec.gob.firmadigital.libreria.certificate.ec.darkcam;

import ec.gob.firmadigital.libreria.certificate.Certificado;
import ec.gob.firmadigital.libreria.certificate.CertificadoOids.Subj;
import ec.gob.firmadigital.libreria.exceptions.EntidadCertificadoraNoValidaException;
import static ec.gob.firmadigital.libreria.utils.BouncyCastleUtils.certificateHasPolicy2;
import java.security.cert.X509Certificate;

/**
 * Permite construir certificados tipo {@link CertificadoDarkcamFactory} a
 * partir de certificados X509Certificate.
 *
 * @author DARKCAM S.A.
 */
public class CertificadoDarkcamFactory {

    public static boolean esCertificadoDeDarkcam(X509Certificate certificado) {
        return (certificateHasPolicy2(certificado, Subj.OID_CERTIFICADO_PERSONA_NATURAL_DARKCAM)
                || certificateHasPolicy2(certificado, Subj.OID_CERTIFICADO_MIEMBRO_EMPRESA_DARKCAM)
                || certificateHasPolicy2(certificado, Subj.OID_CERTIFICADO_REPRESENTANTE_LEGAL_DARKCAM)
                || certificateHasPolicy2(certificado, Subj.OID_CERTIFICADO_SELLO_ELECTRONICO_DARKCAM));
    }

    /**
     * Alias para esCertificadoDeDarkcam (compatibilidad)
     */
    public static boolean esCertificadoDarkcam(X509Certificate certificado) {
        return esCertificadoDeDarkcam(certificado);
    }

    public static Certificado construir(X509Certificate certificado) throws EntidadCertificadoraNoValidaException {
        // Persona Natural (con o sin RUC - se diferencian por presencia del campo Organization Identifier 2.5.4.97)
        if (certificateHasPolicy2(certificado, Subj.OID_CERTIFICADO_PERSONA_NATURAL_DARKCAM)) {
            return new CertificadoPersonaNaturalSubjDarkcam(certificado);
        } // Sello Electrónico
        else if (certificateHasPolicy2(certificado, Subj.OID_CERTIFICADO_SELLO_ELECTRONICO_DARKCAM)) {
            return new CertificadoSelloElectronicoSubjDarkcam(certificado);
        } // Miembro de Empresa
        else if (certificateHasPolicy2(certificado, Subj.OID_CERTIFICADO_MIEMBRO_EMPRESA_DARKCAM)) {
            return new CertificadoMiembroEmpresaSubjDarkcam(certificado);
        } // Representante Legal
        else if (certificateHasPolicy2(certificado, Subj.OID_CERTIFICADO_REPRESENTANTE_LEGAL_DARKCAM)) {
            return new CertificadoRepresentanteLegalSubjDarkcam(certificado);
        } else {
            throw new EntidadCertificadoraNoValidaException("Certificado de DARKCAM sin categorizar!");
        }
    }
}
