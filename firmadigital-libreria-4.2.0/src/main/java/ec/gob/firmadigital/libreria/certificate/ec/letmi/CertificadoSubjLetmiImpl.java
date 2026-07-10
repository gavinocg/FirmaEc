/*
 * Copyright (C) 2025
 * Authors: Letmi
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
package ec.gob.firmadigital.libreria.certificate.ec.letmi;

import ec.gob.firmadigital.libreria.certificate.Certificado;
import static ec.gob.firmadigital.libreria.certificate.CertificadoOids.Subj.*;

import java.security.cert.X509Certificate;

/**
 * Certificado emitido por Letmi y que sigue la estructura de la resolucion de
 * ARCOTEL.
 *
 * @author Letmi
 */
public class CertificadoSubjLetmiImpl extends Certificado {

    public CertificadoSubjLetmiImpl(X509Certificate certificado) {
        super(certificado);
        super.cargarSubjectName();
    }

    public String getCedulaPasaporte() {
        return getSubjectField(OID_CEDULA_PASAPORTE);
    }

    public String getNombres() {
        return getSubjectField(OID_NOMBRES);
    }

    public String getPrimerApellido() {
        return getSubjectField(OID_APELLIDOS);
    }

    public String getSegundoApellido() {
        return "";
    }

    public String getDireccion() {
        return "";
    }

    public String getTelefono() {
        return "";
    }

    public String getCiudad() {
        return getSubjectField(OID_CIUDAD);
    }

    public String getPais() {
        return getSubjectField(OID_PAIS);
    }

    public String getRuc() {
        return getSubjectField(OID_RUC);
    }

}
