/*
 * Copyright (C) 2025
 * Authors: Alpha Technologies Cia. Ltda., Security Data, Misael Fernández
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
package ec.gob.firmadigital.libreria.certificate;

/**
 * Clase contenedora para los Identificadores de Objeto (OIDs) utilizados en
 * certificados digitales.
 *
 * Agrupa los OIDs en clases anidadas estáticas según su ubicación dentro del
 * certificado (Subject o Extensions) para una mejor organización y claridad.
 */
public final class CertificadoOids {

    private CertificadoOids() {
    }

    /**
     * OIDs encontrados en el Subject del certificado X.509.
     */
    public static final class Subj {

        // OIDs de Campos del Certificado.
        public static final String OID_COMMON_NAME = "2.5.4.3";
        public static final String OID_CEDULA_PASAPORTE = "2.5.4.5";
        public static final String OID_APELLIDOS = "2.5.4.4";
        public static final String OID_NOMBRES = "2.5.4.42";
        public static final String OID_PAIS = "2.5.4.6";
        public static final String OID_CIUDAD = "2.5.4.7";
        public static final String OID_RUC = "2.5.4.97";
        public static final String OID_ORGANIZACION = "2.5.4.10";
        public static final String OID_CARGO = "2.5.4.12";

        private Subj() {
        }

        // OIDs de tipo de certificado Alpha Technologies Cia. Ltda.
        public static final String OID_CERTIFICADO_PERSONA_NATURAL_ALPHA_TECHNOLOGIES = "1.3.6.1.4.1.56105.2.1.1";
        public static final String OID_CERTIFICADO_MIEMBRO_EMPRESA_ALPHA_TECHNOLOGIES = "1.3.6.1.4.1.56105.2.2.1";
        public static final String OID_CERTIFICADO_REPRESENTANTE_LEGAL_ALPHA_TECHNOLOGIES = "1.3.6.1.4.1.56105.2.3.1";

        // OIDs de tipo de certificado Letmi
        public static final String OID_CERTIFICADO_PERSONA_NATURAL_LETMI = "1.3.6.1.4.1.62566.2.1.2";
        public static final String OID_CERTIFICADO_MIEMBRO_EMPRESA_LETMI = "1.3.6.1.4.1.62566.2.4.2";
        public static final String OID_CERTIFICADO_REPRESENTANTE_LEGAL_LETMI = "1.3.6.1.4.1.62566.2.3.2";

        // OIDs de tipo de certificado AppFirmas
        public static final String OID_CERTIFICADO_PERSONA_NATURAL_APP_FIRMAS = "1.3.6.1.4.1.62431.2.1.1";
        public static final String OID_CERTIFICADO_MIEMBRO_EMPRESA_APP_FIRMAS = "1.3.6.1.4.1.62431.2.2.1";
        public static final String OID_CERTIFICADO_REPRESENTANTE_LEGAL_APP_FIRMAS = "1.3.6.1.4.1.62431.2.3.1";

        // OIDs de tipo de certificado Darkcam S.A. (Normativa ARCOTEL 2026)
        // Persona Natural (SIN RUC y CON RUC usan el mismo OID, se diferencian por Organization Identifier 2.5.4.97)
        public static final String OID_CERTIFICADO_PERSONA_NATURAL_DARKCAM = "1.3.6.1.4.1.64482.2.1.1";
        public static final String OID_CERTIFICADO_MIEMBRO_EMPRESA_DARKCAM = "1.3.6.1.4.1.64482.2.2.1";
        public static final String OID_CERTIFICADO_SELLO_ELECTRONICO_DARKCAM = "1.3.6.1.4.1.64482.2.2.2";
        public static final String OID_CERTIFICADO_REPRESENTANTE_LEGAL_DARKCAM = "1.3.6.1.4.1.64482.2.3.1";

        // OIDs de tipo de certificado PrimeCoreLat S.A.S.
        public static final String OID_CERTIFICADO_PERSONA_NATURAL_PRIMECORELAT = "1.3.6.1.4.1.63542.2.1.1";
        public static final String OID_CERTIFICADO_MIEMBRO_EMPRESA_PRIMECORELAT = "1.3.6.1.4.1.63542.2.2.1";
        public static final String OID_CERTIFICADO_REPRESENTANTE_LEGAL_PRIMECORELAT = "1.3.6.1.4.1.63542.2.3.1";
        public static final String OID_CERTIFICADO_SELLO_ELECTRONICO_PRIMECORELAT = "1.3.6.1.4.1.63542.2.4.1";

        // OIDs de tipo de certificado SECURITY_DATA
        public static final String OID_CERTIFICADO_PERSONA_NATURAL_SECURITY_DATA = "1.3.6.1.4.1.37746.2.1.1";
        public static final String OID_CERTIFICADO_PERSONA_NATURAL_DSCF_SECURITY_DATA = "1.3.6.1.4.1.37746.2.1.2";
        public static final String OID_CERTIFICADO_MIEMBRO_EMPRESA_SECURITY_DATA = "1.3.6.1.4.1.37746.2.2.1";
        public static final String OID_CERTIFICADO_MIEMBRO_EMPRESA_DSCF_SECURITY_DATA = "1.3.6.1.4.1.37746.2.2.2";
        public static final String OID_CERTIFICADO_REPRESENTANTE_LEGAL_SECURITY_DATA = "1.3.6.1.4.1.37746.2.3.1";
        public static final String OID_CERTIFICADO_REPRESENTANTE_LEGAL_DSCF_SECURITY_DATA = "1.3.6.1.4.1.37746.2.3.2";
        public static final String OID_CERTIFICADO_SELLO_ELECTRONICO_SECURITY_DATA = "1.3.6.1.4.1.37746.102.2.4.1";
        public static final String OID_CERTIFICADO_SELLO_ELECTRONICO_DSCF_SECURITY_DATA = "1.3.6.1.4.1.37746.102.2.4.2";
        public static final String OID_CERTIFICADO_SELLO_TIEMPO_DSCF_SECURITY_DATA = "1.3.6.1.4.1.37746.102.2.5.1";
    }

    /**
     * OIDs encontrados en las extensiones del certificado X.509.
     */
    public static final class Ext {

        private Ext() {
        }

        // OIDs de tipo de certificado Alpha Technologies Cia. Ltda.
        public static final String OID_CERTIFICADO_PERSONA_NATURAL_ALPHA_TECHNOLOGIES = "1.3.6.1.4.1.56105.2.1";
        public static final String OID_CERTIFICADO_PERSONA_JURIDICA_ALPHA_TECHNOLOGIES = "1.3.6.1.4.1.56105.2.2";
        public static final String OID_CERTIFICADO_MIEMBRO_EMPRESA_ALPHA_TECHNOLOGIES = "1.3.6.1.4.1.56105.2.3";

        // OIDs de Campos del Certificado.
        public static final String OID_CEDULA_PASAPORTE = "1.3.6.1.4.1.56105.3.1";
        public static final String OID_NOMBRES = "1.3.6.1.4.1.56105.3.2";
        public static final String OID_APELLIDO_1 = "1.3.6.1.4.1.56105.3.3";
        public static final String OID_APELLIDO_2 = "1.3.6.1.4.1.56105.3.4";
        public static final String OID_CARGO = "1.3.6.1.4.1.56105.3.5";
        public static final String OID_INSTITUCION = "1.3.6.1.4.1.56105.3.6";
        public static final String OID_DIRECCION = "1.3.6.1.4.1.56105.3.7";
        public static final String OID_TELEFONO = "1.3.6.1.4.1.56105.3.8";
        public static final String OID_CIUDAD = "1.3.6.1.4.1.56105.3.9";
        public static final String OID_RAZON_SOCIAL = "1.3.6.1.4.1.56105.3.10";
        public static final String OID_RUC = "1.3.6.1.4.1.56105.3.11";
        public static final String OID_PAIS = "1.3.6.1.4.1.56105.3.12";
    }
}
