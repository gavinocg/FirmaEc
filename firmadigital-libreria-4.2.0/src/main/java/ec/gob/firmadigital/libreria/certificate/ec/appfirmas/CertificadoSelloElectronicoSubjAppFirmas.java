/*
 * Copyright (C) 2025
 * Authors: AppFirmas
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
package ec.gob.firmadigital.libreria.certificate.ec.appfirmas;

import ec.gob.firmadigital.libreria.certificate.ec.CertificadoMiembroEmpresa;
import static ec.gob.firmadigital.libreria.certificate.CertificadoOids.Subj.*;

import java.security.cert.X509Certificate;

/**
 * Certificado de Miembro Empresa emitido por AppFirmas
 *
 * @author AppFirmas
 */
public class CertificadoSelloElectronicoSubjAppFirmas extends CertificadoSubjAppFirmasImpl
        implements CertificadoMiembroEmpresa {

    public CertificadoSelloElectronicoSubjAppFirmas(X509Certificate certificado) {
        super(certificado);
    }

    @Override
    public String getRazonSocial() {
        return getSubjectField(OID_ORGANIZACION);
    }

    @Override
    public String getCargo() {
        return getSubjectField(OID_CARGO);
    }
}
