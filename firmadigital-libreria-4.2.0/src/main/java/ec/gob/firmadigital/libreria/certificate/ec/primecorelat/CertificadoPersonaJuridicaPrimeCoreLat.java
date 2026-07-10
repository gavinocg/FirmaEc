/*
 * Copyright (C) 2025
 * Authors: Misael Fernández, PrimeCoreLat
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
package ec.gob.firmadigital.libreria.certificate.ec.primecorelat;

import java.security.cert.X509Certificate;

import ec.gob.firmadigital.libreria.certificate.ec.CertificadoPersonaJuridica;

/**
 * Certificado de persona jurídica emitido por PRIMECORELAT.
 *
 * @author Henry Carrera <henry@hyrserv.com>
 */
public class CertificadoPersonaJuridicaPrimeCoreLat extends CertificadoPrimeCoreLat
        implements CertificadoPersonaJuridica {

    public CertificadoPersonaJuridicaPrimeCoreLat(X509Certificate certificado) {
        super(certificado);
    }

    @Override
    public String getRazonSocial() {
        return super.getRazonSocial();
    }

    @Override
    public String getRuc() {
        return super.getRuc();
    }

    @Override
    public String getCedulaPasaporte() {
        return super.getCedulaPasaporte();
    }

    @Override
    public String getNombres() {
        return super.getNombres();
    }

    @Override
    public String getPrimerApellido() {
        return super.getPrimerApellido();
    }

    @Override
    public String getSegundoApellido() {
        return super.getSegundoApellido();
    }

    @Override
    public String getCargo() {
        return super.getCargo();
    }

    @Override
    public String getDireccion() {
        return super.getDireccion();
    }

    @Override
    public String getTelefono() {
        return super.getTelefono();
    }

    @Override
    public String getCiudad() {
        return super.getCiudad();
    }

    @Override
    public String getPais() {
        return super.getPais();
    }
}
