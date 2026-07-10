/*
 * Copyright (C) 2020 
 * Authors: Ricardo Arguello, Misael Fernández, Security Data
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
package ec.gob.firmadigital.libreria.certificate.ec.securitydata;

import static ec.gob.firmadigital.libreria.certificate.ec.securitydata.CertificadoSecurityData.OID_SELLADO_TIEMPO;
import static ec.gob.firmadigital.libreria.certificate.ec.securitydata.CertificadoSecurityData.OID_TIPO_FUNCIONARIO_PUBLICO;
import static ec.gob.firmadigital.libreria.certificate.ec.securitydata.CertificadoSecurityData.OID_TIPO_MIEMBRO_EMPRESA;
import static ec.gob.firmadigital.libreria.certificate.ec.securitydata.CertificadoSecurityData.OID_TIPO_PERSONA_JURIDICA_EMPRESA;
import static ec.gob.firmadigital.libreria.certificate.ec.securitydata.CertificadoSecurityData.OID_TIPO_PERSONA_NATURAL;
import static ec.gob.firmadigital.libreria.certificate.ec.securitydata.CertificadoSecurityData.OID_TIPO_PERSONA_NATURAL_PROFESIONAL;
import static ec.gob.firmadigital.libreria.certificate.ec.securitydata.CertificadoSecurityData.OID_TIPO_REPRESENTANTE_LEGAL;
import ec.gob.firmadigital.libreria.certificate.Certificado;
import ec.gob.firmadigital.libreria.certificate.CertificadoOids.Subj;
import ec.gob.firmadigital.libreria.exceptions.EntidadCertificadoraNoValidaException;
import static ec.gob.firmadigital.libreria.utils.BouncyCastleUtils.certificateHasPolicy;
import static ec.gob.firmadigital.libreria.utils.BouncyCastleUtils.certificateHasPolicy2;

import java.security.cert.X509Certificate;

/**
 * Permite construir certificados tipo CertificadoSecurityData a partir de
 * certificados X509Certificate.
 *
 * @author Ricardo Arguello, Freddy Pico
 */
public class CertificadoSecurityDataFactory {

    public static boolean esCertificadoDeSecurityData(X509Certificate certificado) {
        return (certificateHasPolicy(certificado, OID_TIPO_PERSONA_NATURAL)
                || certificateHasPolicy(certificado, OID_TIPO_PERSONA_JURIDICA_EMPRESA)
                || certificateHasPolicy(certificado, OID_TIPO_REPRESENTANTE_LEGAL)
                || certificateHasPolicy(certificado, OID_TIPO_MIEMBRO_EMPRESA)
                || certificateHasPolicy(certificado, OID_TIPO_FUNCIONARIO_PUBLICO)
                || certificateHasPolicy(certificado, OID_TIPO_PERSONA_NATURAL_PROFESIONAL)
                || certificateHasPolicy(certificado, OID_SELLADO_TIEMPO)
                //RESOLUCION-ARCOTEL-2024-0176
                || certificateHasPolicy2(certificado, Subj.OID_CERTIFICADO_PERSONA_NATURAL_SECURITY_DATA)
                || certificateHasPolicy2(certificado, Subj.OID_CERTIFICADO_PERSONA_NATURAL_DSCF_SECURITY_DATA)
                || certificateHasPolicy2(certificado, Subj.OID_CERTIFICADO_REPRESENTANTE_LEGAL_SECURITY_DATA)
                || certificateHasPolicy2(certificado, Subj.OID_CERTIFICADO_REPRESENTANTE_LEGAL_DSCF_SECURITY_DATA)
                || certificateHasPolicy2(certificado, Subj.OID_CERTIFICADO_MIEMBRO_EMPRESA_SECURITY_DATA)
                || certificateHasPolicy2(certificado, Subj.OID_CERTIFICADO_MIEMBRO_EMPRESA_DSCF_SECURITY_DATA)
                || certificateHasPolicy2(certificado, Subj.OID_CERTIFICADO_SELLO_ELECTRONICO_SECURITY_DATA)
                || certificateHasPolicy2(certificado, Subj.OID_CERTIFICADO_SELLO_ELECTRONICO_DSCF_SECURITY_DATA)
                || certificateHasPolicy2(certificado, Subj.OID_CERTIFICADO_SELLO_TIEMPO_DSCF_SECURITY_DATA));
    }

    public static Certificado construir(X509Certificate certificado) throws EntidadCertificadoraNoValidaException {
        if (certificateHasPolicy(certificado, OID_TIPO_PERSONA_NATURAL)) {
            return new CertificadoPersonaNaturalSecurityData(certificado);
        } else if (certificateHasPolicy(certificado, OID_TIPO_PERSONA_JURIDICA_EMPRESA)) {
            return new CertificadoPersonaJuridicaSecurityData(certificado);
        } else if (certificateHasPolicy(certificado, OID_TIPO_REPRESENTANTE_LEGAL)) {
            return new CertificadoRepresentanteLegalSecurityData(certificado);
        } else if (certificateHasPolicy(certificado, OID_TIPO_MIEMBRO_EMPRESA)) {
            return new CertificadoMiembroEmpresaSecurityData(certificado);
        } else if (certificateHasPolicy(certificado, OID_TIPO_FUNCIONARIO_PUBLICO)) {
            return new CertificadoFuncionarioPublicoSecurityData(certificado);
        } else if (certificateHasPolicy(certificado, OID_TIPO_PERSONA_NATURAL_PROFESIONAL)) {
            return new CertificadoPersonaNaturalSecurityData(certificado);
        } else if (certificateHasPolicy(certificado, OID_SELLADO_TIEMPO)) {
            return new CertificadoSelladoTiempoSecurityData(certificado);
        } //RESOLUCION-ARCOTEL-2024-0176
        else if (certificateHasPolicy2(certificado, Subj.OID_CERTIFICADO_PERSONA_NATURAL_SECURITY_DATA)) {
            return new CertificadoPersonaNaturalSubjSecurityData(certificado);
        } else if (certificateHasPolicy2(certificado, Subj.OID_CERTIFICADO_PERSONA_NATURAL_DSCF_SECURITY_DATA)) {
            return new CertificadoPersonaNaturalSubjSecurityData(certificado);
        } else if (certificateHasPolicy2(certificado, Subj.OID_CERTIFICADO_REPRESENTANTE_LEGAL_SECURITY_DATA)) {
            return new CertificadoRepresentanteLegalSubjSecurityData(certificado);
        } else if (certificateHasPolicy2(certificado, Subj.OID_CERTIFICADO_REPRESENTANTE_LEGAL_DSCF_SECURITY_DATA)) {
            return new CertificadoRepresentanteLegalSubjSecurityData(certificado);
        } else if (certificateHasPolicy2(certificado, Subj.OID_CERTIFICADO_MIEMBRO_EMPRESA_SECURITY_DATA)) {
            return new CertificadoMiembroEmpresaSubjSecurityData(certificado);
        } else if (certificateHasPolicy2(certificado, Subj.OID_CERTIFICADO_MIEMBRO_EMPRESA_DSCF_SECURITY_DATA)) {
            return new CertificadoMiembroEmpresaSubjSecurityData(certificado);
        } else if (certificateHasPolicy2(certificado, Subj.OID_CERTIFICADO_SELLO_ELECTRONICO_SECURITY_DATA)) {
            return new CertificadoSelloElectronicoSubjSecurityData(certificado);
        } else if (certificateHasPolicy2(certificado, Subj.OID_CERTIFICADO_SELLO_ELECTRONICO_DSCF_SECURITY_DATA)) {
            return new CertificadoSelloElectronicoSubjSecurityData(certificado);
        } else if (certificateHasPolicy2(certificado, Subj.OID_CERTIFICADO_SELLO_TIEMPO_DSCF_SECURITY_DATA)) {
            return new CertificadoSelladoTiempoSubjSecurityData(certificado);
        } else {
//            throw new EntidadCertificadoraNoValidaException("Tipo Certificado de SecurityData desconocido!");
            return null;
        }
    }
}
