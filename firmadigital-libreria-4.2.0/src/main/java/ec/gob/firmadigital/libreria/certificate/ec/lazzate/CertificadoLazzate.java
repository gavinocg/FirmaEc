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

import java.io.IOException;
import java.security.cert.X509Certificate;

import ec.gob.firmadigital.libreria.certificate.CertUtils;

/**
 * Certificado emitido por Lazzate.
 *
 * @author Henry Carrera <henry@hyrserv.com>
 */
public abstract class CertificadoLazzate {

    // OIDs de tipo de certificado:
    public static final String OID_CERTIFICADO_PERSONA_NATURAL = "1.3.6.1.4.1.59382.2.1";
    public static final String OID_CERTIFICADO_PERSONA_JURIDICA_EMPRESA = "1.3.6.1.4.1.59382.2.2";
    public static final String OID_CERTIFICADO_REPRESENTANTE_LEGAL = "1.3.6.1.4.1.59382.2.3";
    public static final String OID_CERTIFICADO_MIEMBRO_EMPRESA = "1.3.6.1.4.1.59382.2.4";
    public static final String OID_CERTIFICADO_FUNCIONARIO_PUBLICO = "1.3.6.1.4.1.59382.2.5";
    public static final String OID_CERTIFICADO_SSL = "1.3.6.1.4.1.59382.2.6";
    public static final String OID_CERTIFICADO_PERSONA_NATURAL_PROFESIONAL = "1.3.6.1.4.1.59382.2.7";

    // OIDs de Campos del Certificado:
    public static final String OID_CEDULA_PASAPORTE = "1.3.6.1.4.1.59382.3.1";
    public static final String OID_NOMBRES = "1.3.6.1.4.1.59382.3.2";
    public static final String OID_APELLIDO_1 = "1.3.6.1.4.1.59382.3.3";
    public static final String OID_APELLIDO_2 = "1.3.6.1.4.1.59382.3.4";
    public static final String OID_CARGO = "1.3.6.1.4.1.59382.3.5";
    public static final String OID_INSTITUCION = "1.3.6.1.4.1.59382.3.6";
    public static final String OID_DIRECCION = "1.3.6.1.4.1.59382.3.7";
    public static final String OID_TELEFONO = "1.3.6.1.4.1.59382.3.8";
    public static final String OID_CIUDAD = "1.3.6.1.4.1.59382.3.9";
    public static final String OID_RAZON_SOCIAL = "1.3.6.1.4.1.59382.3.10";
    public static final String OID_RUC = "1.3.6.1.4.1.59382.3.11";
    public static final String OID_PAIS = "1.3.6.1.4.1.59382.3.12";

    /**
     * Certificado a analizar
     */
    private final X509Certificate certificado;

    public CertificadoLazzate(X509Certificate certificado) {
        this.certificado = certificado;
    }

    /**
     * Retorna el valor de la extension, y una cadena vacia si no existe.
     *
     * @param oid
     * @return
     */
    protected String obtenerExtension(String oid) {
        try {
            String valor = CertUtils.getExtensionValueSubjectAlternativeNames(certificado, oid);
            return (valor != null) ? valor : "";
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
