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

import java.security.cert.X509Certificate;
import ec.gob.firmadigital.libreria.certificate.ec.CertificadoPersonaNatural;

/**
 * Certificado de persona natural emitido por Alpha Technologies Cia. Ltda.
 *
 * @author Alpha Technologies Cia. Ltda.
 */
public class CertificadoPersonaNaturalAlphaTechnologies extends CertificadoAlphaTechnologiesImpl
        implements CertificadoPersonaNatural {

    public CertificadoPersonaNaturalAlphaTechnologies(X509Certificate certificado) {
        super(certificado);
    }

}
