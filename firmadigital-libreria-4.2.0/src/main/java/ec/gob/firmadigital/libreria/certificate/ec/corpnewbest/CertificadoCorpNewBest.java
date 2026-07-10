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

import java.io.IOException;
import java.security.cert.X509Certificate;

import ec.gob.firmadigital.libreria.certificate.CertUtils;

/**
 * Certificado emitido por CorpNewBest
 *
 * @author Pedro Reyes
 */
public abstract class CertificadoCorpNewBest {

    // OIDs de Tipo de Certificado
    public static final String OID_TIPO_PERSONA_NATURAL = "1.3.6.1.4.1.34380.2.7";
    public static final String OID_TIPO_PERSONA_JURIDICA = "1.3.6.1.4.1.34380.2.8";
    public static final String OID_TIPO_MIEMBRO_EMPRESA = "1.3.6.1.4.1.34380.2.10";

    // OIDs de Campos del Certificado:
    public static final String OID_CEDULA_PASAPORTE = "1.3.6.1.4.1.34380.3.1";
    public static final String OID_NOMBRES = "1.3.6.1.4.1.34380.3.2";
    public static final String OID_PRIMER_APELLIDO = "1.3.6.1.4.1.34380.3.3";
    public static final String OID_SEGUNDO_APELLIDO = "1.3.6.1.4.1.34380.3.4";
    public static final String OID_CARGO = "1.3.6.1.4.1.34380.3.5";
    public static final String OID_INSTITUCION = "1.3.6.1.4.1.34380.3.6";
    public static final String OID_DIRECCION = "1.3.6.1.4.1.34380.3.7";
    public static final String OID_TELEFONO = "1.3.6.1.4.1.34380.3.8";
    public static final String OID_CIUDAD = "1.3.6.1.4.1.34380.3.9";
    public static final String OID_RAZON_SOCIAL = "1.3.6.1.4.1.34380.3.10";
    public static final String OID_RUC = "1.3.6.1.4.1.34380.3.11";
    public static final String OID_PAIS = "1.3.6.1.4.1.34380.3.12";

    /**
     * Certificado a analizar
     */
    private final X509Certificate certificado;

    /**
     * Permite analizar los contenidos de un X509Certificate segun las OIDs de
     * Security Data.
     *
     * @param certificado
     */
    public CertificadoCorpNewBest(X509Certificate certificado) {
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
            String valor = CertUtils.getExtensionValue(certificado, oid);
            return (valor != null) ? valor : "";
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public String getNombres() {
        return obtenerExtension(OID_NOMBRES);
    }

    public String getPrimerApellido() {
        return obtenerExtension(OID_PRIMER_APELLIDO);
    }

    public String getSegundoApellido() {
        return obtenerExtension(OID_SEGUNDO_APELLIDO);
    }
}
