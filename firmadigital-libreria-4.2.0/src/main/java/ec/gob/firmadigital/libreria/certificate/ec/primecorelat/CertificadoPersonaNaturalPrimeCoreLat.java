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

import ec.gob.firmadigital.libreria.certificate.ec.CertificadoPersonaNatural;

/**
 * Certificado de persona natural emitido por PRIMECORELAT.
 *
 * @author Henry Carrera <henry@hyrserv.com>
 */
public class CertificadoPersonaNaturalPrimeCoreLat extends CertificadoPrimeCoreLat
        implements CertificadoPersonaNatural {

    public CertificadoPersonaNaturalPrimeCoreLat(X509Certificate certificado) {
        super(certificado);
    }
}
