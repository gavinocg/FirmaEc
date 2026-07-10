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

import static ec.gob.firmadigital.libreria.certificate.CertificadoOids.Ext.*;

import java.security.cert.X509Certificate;

/**
 * Certificado emitido por Alpha Technologies Cia. Ltda. El certificado contiene
 * OIDs como extensiones.
 *
 * @author Alpha Technologies Cia. Ltda.
 */
public class CertificadoAlphaTechnologiesImpl extends Certificado {

    public CertificadoAlphaTechnologiesImpl(X509Certificate certificado) {
        super(certificado);
    }

    public String getCedulaPasaporte() {
        return obtenerExtension(OID_CEDULA_PASAPORTE);
    }

    public String getNombres() {
        return obtenerExtension(OID_NOMBRES);
    }

    public String getPrimerApellido() {
        return obtenerExtension(OID_APELLIDO_1);
    }

    public String getSegundoApellido() {
        return obtenerExtension(OID_APELLIDO_2);
    }

    public String getCargo() {
        return obtenerExtension(OID_CARGO);
    }

    public String getInstitucion() {
        return obtenerExtension(OID_INSTITUCION);
    }

    public String getDireccion() {
        return obtenerExtension(OID_DIRECCION);
    }

    public String getTelefono() {
        return obtenerExtension(OID_TELEFONO);
    }

    public String getCiudad() {
        return obtenerExtension(OID_CIUDAD);
    }

    public String getPais() {
        return obtenerExtension(OID_PAIS);
    }

    public String getRuc() {
        return obtenerExtension(OID_RUC);
    }

    public String getRazonSocial() {
        return obtenerExtension(OID_RAZON_SOCIAL);
    }

}
